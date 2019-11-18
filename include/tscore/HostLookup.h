/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

/*****************************************************************************
 *
 *  HostLookup.h - Interface to general purpose matcher
 *
 *
 ****************************************************************************/

#pragma once

#include <vector>
#include <array>
#include <string>
#include <string_view>
#include <functional>
#include <unordered_map>

// HostLookup constants
constexpr int HOST_TABLE_DEPTH = 3;  // Controls the max number of levels in the logical tree
constexpr int HOST_ARRAY_MAX   = 8;  // Sets the fixed array size
constexpr int numLegalChars    = 38; // Number of legal characters in the asciiToTable array

class CharIndex;
struct HostBranch;

//
// class HostArray
//
//   Is a fixed size array for holding HostBranch*
//   Allows only sequential access to data
//

class HostArray
{
public:
  /// Element of the @c HostArray.
  struct Item {
    HostBranch *branch{nullptr}; ///< Next branch.
    std::string match_data;      ///< Match data for that branch.
  };
  using Array = std::array<Item, HOST_ARRAY_MAX>;

public:
  bool Insert(std::string_view match_data_in, HostBranch *toInsert);
  HostBranch *Lookup(std::string_view match_data_in, bool bNotProcess);

  Array::iterator
  begin()
  {
    return array.begin();
  }
  Array::iterator
  end()
  {
    return array.begin() + _size;
  }
  size_t
  size()
  {
    return _size;
  }

private:
  int _size{0}; // number of elements currently in the array
  Array array;
};

// The data in the HostMatcher tree is pointers to HostBranches. No duplicates keys permitted in the tree.  To handle
// multiple data items bound the same key, the HostBranch has the lead_indexs array which stores pointers (in the form
// of array indexes) to HostLeaf structs
//
// There is HostLeaf struct for each data item put into the table
//
struct HostLeaf {
  /// Type of leaf.
  enum Type {
    LEAF_INVALID,
    HOST_PARTIAL,
    HOST_COMPLETE,
    DOMAIN_COMPLETE,
    DOMAIN_PARTIAL,
  };
  Type type{LEAF_INVALID};    ///< Type of this leaf instance.
  std::string match;          // Contains a copy of the match data
  bool isNot{false};          // used by any fasssst path ...
  void *opaque_data{nullptr}; // Data associated with this leaf

  HostLeaf() {}
  HostLeaf(std::string_view name, void *data) : opaque_data(data)
  {
    if (!name.empty() && name.front() == '!') {
      name.remove_prefix(1);
      isNot = true;
    }
    match.assign(name);
  }
};

struct HostBranch {
  /// Branch type.
  enum Type {
    HOST_TERMINAL,
    HOST_HASH,
    HOST_INDEX,
    HOST_ARRAY,
  };

  using HostTable = std::unordered_map<std::string_view, HostBranch *>;

  using LeafIndices = std::vector<int>;

  /// Type of data in this branch.
  union Level {
    std::nullptr_t _nil; ///< HOST_TERMINAL
    HostTable *_table;   ///< HOST_HASH
    CharIndex *_index;   ///< HOST_INDEX
    HostArray *_array;   ///< HOST_ARRAY
    void *_ptr;          ///< As generic pointer.
  };

  ~HostBranch();
  int level_idx{0};          // what level in the tree.  the root is level 0
  Type type{HOST_TERMINAL};  // tells what kind of data structure is next_level is
  Level next_level{nullptr}; // opaque pointer to lookup structure
  LeafIndices leaf_indices;  // HostLeaf indices.
  std::string key;
};

//
//  End Host Lookup Helper types
//

struct HostLookupState {
  HostBranch *cur{nullptr};
  int table_level{0};
  int array_index{0};
  std::string_view hostname;      ///< Original host name.
  std::string_view hostname_stub; ///< Remaining host name to search.
};

class HostLookup
{
public:
  using LeafArray = std::vector<HostLeaf>;
  using PrintFunc = std::function<void(void *)>;

  HostLookup(std::string_view name);
  void NewEntry(std::string_view match_data, bool domain_record, void *opaque_data_in);
  void AllocateSpace(int num_entries);
  bool Match(std::string_view host);
  bool Match(std::string_view host, void **opaque_ptr);
  bool MatchFirst(std::string_view host, HostLookupState *s, void **opaque_ptr);
  bool MatchNext(HostLookupState *s, void **opaque_ptr);
  void Print(PrintFunc const &f);
  void Print();

  LeafArray *
  get_leaf_array()
  {
    return &leaf_array;
  }

private:
  using HostTable   = HostBranch::HostTable;
  using LeafIndices = HostBranch::LeafIndices;

  void TableInsert(std::string_view match_data, int index, bool domain_record);
  HostBranch *TableNewLevel(HostBranch *from, std::string_view level_data);
  HostBranch *InsertBranch(HostBranch *insert_in, std::string_view level_data);
  HostBranch *FindNextLevel(HostBranch *from, std::string_view level_data, bool bNotProcess = false);
  bool MatchArray(HostLookupState *s, void **opaque_ptr, LeafIndices &array, bool host_done);
  void PrintHostBranch(HostBranch *hb, PrintFunc const &f);
  HostBranch root;          // The top of the search tree
  LeafArray leaf_array;     // array of all leaves in tree
  std::string matcher_name; // Used for Debug/Warning/Error messages
};

// struct CharIndexBlock
//
//   Used by class CharIndex.  Forms a single level in CharIndex tree
//
struct CharIndexBlock {
  struct Item {
    HostBranch *branch{nullptr};
    std::unique_ptr<CharIndexBlock> block;
  };
  std::array<Item, numLegalChars> array;
};

// class CharIndex - A constant time string matcher intended for
//    short strings in a sparsely populated DNS partition
//
//    Creates a look up table for character in data string
//
//    Mapping from character to table index is done by
//      asciiToTable[]
//
//    The illegalKey hash table is side structure for any
//     entries that contain illegal hostname characters that
//     we can not index into the normal table
//
//    Example: com
//      c maps to 13, o maps to 25, m maps to 23
//
//                             CharIndexBlock         CharIndexBlock
//                             -----------         ------------
//                           0 |    |    |         |    |     |
//                           . |    |    |         |    |     |
//    CharIndexBlock         . |    |    |         |    |     |
//    ----------             . |    |    |         |    |     |
//  0 |   |    |             . |    |    |   |-->23| ptr|  0  |  (ptr is to the
//  . |   |    |   |-------->25| 0  |   -----|     |    |     |   hostBranch for
//  . |   |    |   |         . |    |    |         |    |     |   domain com)
// 13 | 0 |  --|---|         . |    |    |         |    |     |
//  . |   |    |             . |    |    |         |    |     |
//  . |   |    |               |    |    |         |    |     |
//  . |   |    |               |    |    |         |    |     |
//    |   |    |               -----------         -----------|
//    |   |    |
//    |   |    |
//    |   |    |
//    |--------|
//
//
class CharIndex
{
public:
  struct iterator : public std::iterator<std::forward_iterator_tag, HostBranch> {
    using self_type = iterator;

    struct State {
      int index{-1};
      CharIndexBlock *block{nullptr};
    };

    value_type *operator->();
    value_type &operator*();
    bool operator==(self_type const &that) const;
    bool operator!=(self_type const &that) const;
    self_type &operator++();

    // Current level.
    int cur_level{-1};

    // Where we got the last element from
    State state;

    //  Queue of the above levels
    std::vector<State> q;

    // internal methods
    self_type &advance();
  };

  ~CharIndex();
  void Insert(std::string_view match_data, HostBranch *toInsert);
  HostBranch *Lookup(std::string_view match_data);

  iterator begin();
  iterator end();

private:
  CharIndexBlock root;
  using Table = std::unordered_map<std::string_view, HostBranch *>;
  std::unique_ptr<Table> illegalKey;
};
