#let ink = rgb("#18212f")
#let muted = rgb("#647084")
#let rule = rgb("#d8dee8")
#let accent = rgb("#1f6feb")
#let accent-soft = rgb("#eef5ff")
#let code-bg = rgb("#f6f8fb")

#set page(
  paper: "a4",
  margin: (x: 2.1cm, y: 2.0cm),
  numbering: "1",
  header: context {
    if counter(page).get().first() > 1 [
      #set text(size: 8.5pt, fill: muted)
      #grid(
        columns: (1fr, auto),
        align: (left, right),
        [AgentGuardian 技术手册],
        [#datetime.today().year()],
      )
      #line(length: 100%, stroke: 0.35pt + rule)
    ]
  },
  footer: context {
    if counter(page).get().first() > 1 [
      #line(length: 100%, stroke: 0.35pt + rule)
      #align(right)[#text(size: 8.5pt, fill: muted)[#counter(page).display()]]
    ]
  },
)
#set text(font: ("Noto Sans CJK SC", "Noto Sans"), size: 9.8pt, fill: ink, lang: "zh")
#set par(justify: true, leading: 0.68em, spacing: 0.62em)
#set list(indent: 1.2em, body-indent: 0.45em)
#set enum(indent: 1.2em, body-indent: 0.45em)
#set table(
  stroke: (x, y) => if y == 0 { 0.65pt + accent } else { 0.35pt + rule },
  inset: (x: 7pt, y: 5pt),
  align: left,
  fill: (x, y) => if y == 0 { accent-soft } else { none },
)
#show table.cell.where(y: 0): set text(weight: "semibold", fill: ink)
#show raw.where(block: true): it => block(
  fill: code-bg,
  stroke: 0.45pt + rule,
  radius: 2pt,
  inset: 7pt,
  above: 0.45em,
  below: 0.65em,
)[#text(font: "JetBrainsMono NF", size: 8.7pt, fill: rgb("#253040"), it)]
#show raw.where(block: false): it => box(
  fill: code-bg,
  stroke: 0.35pt + rule,
  radius: 2pt,
  inset: (x: 3pt, y: 1pt),
)[#text(font: "JetBrainsMono NF", size: 8.2pt, fill: rgb("#253040"), it)]
#set heading(numbering: "1.")
#show heading.where(level: 1): it => {
  pagebreak()
  block(above: 0pt, below: 0.65em)[
    #text(size: 19pt, weight: "bold", fill: ink, it.body)
    #v(0.25em)
    #line(length: 42%, stroke: 1.2pt + accent)
  ]
}
#show heading.where(level: 2): it => {
  v(0.95em)
  text(size: 13.2pt, weight: "bold", fill: ink, it.body)
  v(0.1em)
}
#show heading.where(level: 3): it => {
  v(0.55em)
  text(size: 10.8pt, weight: "semibold", fill: accent, it.body)
  v(0.05em)
}

#v(2.2cm)
#block(width: 100%)[
  #line(length: 100%, stroke: 1.6pt + accent)
  #v(1.2cm)
  #text(size: 34pt, weight: "bold", fill: ink)[AgentGuardian]
  #v(0.25cm)
  #text(size: 15pt, fill: muted)[技术手册]
  #v(0.25cm)
  #text(size: 9.6pt, fill: accent)[eBPF + Cryptographic Isolation Zero-Trust Sandbox for LLM Agents]
  #v(0.55cm)
  #block(width: 70%)[
    #text(size: 10.8pt, fill: muted)[
      面向 LLM Agent 的组件化纵深防御零信任沙箱系统。本文档以当前实现为准，描述 eBPF 内核探针、Frida 动态插桩、审计引擎、攻击场景构造以及 Dashboard 的工程结构。
    ]
  ]
  #v(2.2cm)
  #grid(
    columns: (auto, 1fr),
    column-gutter: 1.4cm,
    row-gutter: 0.35cm,
    [#text(fill: muted)[Version]],
    [#text(weight: "semibold")[0.1.0]],
    [#text(fill: muted)[Date]],
    [#text(weight: "semibold")[2026 年 6 月]],
    [#text(fill: muted)[License]],
    [#text(weight: "semibold")[MIT]],
  )
  #v(2.1cm)
  #line(length: 32%, stroke: 0.8pt + rule)
]

#pagebreak()
#align(left)[
  #text(size: 18pt, weight: "bold", fill: ink)[目录]
  #v(0.35cm)
  #line(length: 30%, stroke: 1pt + accent)
]
#v(0.6cm)
#outline(title: none, indent: 1.2em, depth: 3)
