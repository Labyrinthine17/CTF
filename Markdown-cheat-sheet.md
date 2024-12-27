# Markdown Cheat Sheet

Reference: <https://github.com/falkobanaszak/vscode-management/blob/main/Markdown%20Resources/markdown-cheat-sheet.md?plain=1>

- [Markdown Cheat Sheet](#markdown-cheat-sheet)
  - [Basic Syntax](#basic-syntax)
    - [Heading](#heading)
- [H1](#h1)
  - [H2](#h2)
    - [H3](#h3)
    - [Bold](#bold)
    - [Italic](#italic)
    - [Blockquote](#blockquote)
    - [Ordered List](#ordered-list)
    - [Unordered List](#unordered-list)
    - [Toggle list](#toggle-list)
    - [Code](#code)
    - [Horizontal Rule](#horizontal-rule)
    - [Link](#link)
    - [Image](#image)
  - [Extended Syntax](#extended-syntax)
    - [Table](#table)
    - [Fenced Code Block](#fenced-code-block)
    - [Footnote](#footnote)
    - [Heading ID](#heading-id)
    - [My Great Heading {#custom-id}](#my-great-heading-custom-id)
    - [Definition List](#definition-list)
    - [Strikethrough](#strikethrough)
    - [Task List](#task-list)
    - [Emoji](#emoji)
    - [Highlight](#highlight)
    - [Subscript](#subscript)
    - [Superscript](#superscript)

## Basic Syntax

These are the elements outlined in John Gruber’s original design document. All Markdown applications support these elements.

### Heading

# H1

## H2

### H3

### Bold

**bold text**

### Italic

*italicized text*

### Blockquote

> blockquote

### Ordered List

1. First item
2. Second item
3. Third item

### Unordered List

- First item
- Second item
- Third item

### Toggle list

<details>
  <summary>Click me</summary>
</details>

### Code

`code`

### Horizontal Rule

---

### Link

[Markdown Guide](https://www.markdownguide.org)

### Image

![alt text](https://www.markdownguide.org/assets/images/tux.png)

## Extended Syntax

These elements extend the basic syntax by adding additional features. Not all Markdown applications support these elements.

### Table

| Syntax | Description |
| ----------- | ----------- |
| Header | Title |
| Paragraph | Text |

### Fenced Code Block

```text
{
  "firstName": "John",
  "lastName": "Smith",
  "age": 25
}
```

### Footnote

Here's a sentence with a footnote. [^1]

[^1]: This is the footnote.

### Heading ID

### My Great Heading {#custom-id}

### Definition List

term
: definition

### Strikethrough

~~The world is flat.~~

### Task List

- [x] Write the press release
- [ ] Update the website
- [ ] Contact the media

### Emoji

That is so funny! :joy:

(See also [Copying and Pasting Emoji](https://www.markdownguide.org/extended-syntax/#copying-and-pasting-emoji))

### Highlight

I need to highlight these ==very important words==.

### Subscript

H~2~O

### Superscript

X^2^
