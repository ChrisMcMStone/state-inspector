graph [
  comment "Created by dottoxml.py"
  directed 1
  IsPlanar 1
  node [
    id 2
    label
    "test2"
  ]
  node [
    id 7
    label
    "intrusive[other]"
  ]
  node [
    id 4
    label
    "wave"
  ]
  node [
    id 9
    label
    "intru[sive[]0,7]"
  ]
  node [
    id 10
    label
    "[wave]"
  ]
  node [
    id 8
    label
    "wave[]"
  ]
  node [
    id 1
    label
    "test"
  ]
  node [
    id 5
    label
    "intrusive"
  ]
  node [
    id 3
    label
    "test3[this]"
  ]
  node [
    id 6
    label
    "wave["
  ]
  edge [
    source 4
    target 5
    label
    ""
  ]
  edge [
    source 6
    target 7
    label
    ""
  ]
  edge [
    source 8
    target 9
    label
    ""
  ]
  edge [
    source 10
    target 5
    label
    ""
  ]
]
