# Tinkerspark

The domain language of Tinkerspark — a desktop workstation for inspecting, diffing, and carefully patching binary files, especially cryptographic formats. This glossary defines the canonical terms and the words we deliberately avoid. It contains no implementation detail.

## Language

### Bytes and editing

**Original**:
The unmodified bytes of a file as it was opened; edits never mutate it and saving never overwrites it.
_Avoid_: base, snapshot

**Edit**:
The user action of replacing a span of selected bytes with new bytes of the same length.
_Avoid_: "patch" as a verb

**Patch**:
The artifact an Edit produces: one same-length replacement of a byte range, layered over the Original.
_Avoid_: "edit" as a noun for the stored change

**Patched view**:
The Original read through its Patches — the effective bytes the hex grid, search, diff, and analysis all operate on.
_Avoid_: working copy

**Patched copy**:
A new file containing the Original with every Patch applied; saving always produces one and never alters the Original.
_Avoid_: save-in-place, overwrite

### Detection and analysis

**Kind**:
The classification detection assigns to a file — content first, extension second; encoding-aware (e.g. armored vs binary, PEM vs DER).
_Avoid_: type, file type

**Format**:
A file format an Analyzer understands (OpenPGP, X.509, SSH, age, JWK, …); one Format spans one or more Kinds.

**Analyzer**:
The component that recognizes a Format and parses a file into its Structure.
_Avoid_: parser

**Confidence**:
How strongly an Analyzer claims a file — None, Low, Medium, or High; when several Analyzers match, the highest-Confidence one is used.

**Analysis**:
The result of running an Analyzer on a file: a Structure together with diagnostics.

**Structure**:
The tree of byte-range-mapped elements an Analysis reveals; the "structure second" lens onto a file.

**Node**:
A single element in the Structure tree — e.g. an OpenPGP packet or a certificate field group; maps to a byte range and may contain Fields and child Nodes.

**Field**:
A named decoded value shown within a Node (e.g. "Algorithm: RSA"), optionally mapped to its own byte sub-range.

**Template**:
A user-supplied description of a binary layout (match rules plus sequential fields) that the built-in custom Analyzer applies as structural guidance, not authoritative parsing.

### Diffing

**Diff**:
A byte-level comparison of two files, and the workspace tab that hosts it.
_Avoid_: diff session

**Change**:
A single region where the two files in a Diff differ, located on each Side.
_Avoid_: difference, ChangedRange

**Side**:
One of the two files under comparison in a Diff: Left or Right.

**Merge**:
Copying one Side's bytes into the other for a single Change; requires an equal-length Change.

**Merged region**:
A Change that has been merged, kept highlighted until the merge is undone — even though it is no longer a difference.

**Focused change**:
The Change currently selected in the Diff's navigator.

## Relationships

- An **Edit** produces a **Patch**
- A **Patch** layers over the **Original** without mutating it
- The **Patched view** is the **Original** overlaid with its **Patches**
- Saving writes a **Patched copy**; it never modifies the **Original**
- Detection assigns each file a **Kind**; a **Kind** maps to a **Format**, and one **Format** spans one or more **Kinds**
- An **Analyzer** handles one **Format** and produces an **Analysis**
- An **Analysis** contains a **Structure** plus diagnostics
- A **Structure** is a tree of **Nodes**; each **Node** maps to a byte range and may hold **Fields** and child **Nodes**
- Clicking a **Node** or **Field** highlights its bytes — the bridge from the structure lens back to the byte lens
- A **Template** is data the custom **Analyzer** interprets to produce a **Structure**; it is not itself an **Analyzer**
- A **Diff** compares two **Sides** (Left and Right) and yields a list of **Changes**
- A **Merge** produces a **Patch** on the receiving **Side**; undoing that **Patch** clears the **Merged region**

## Example dialogue

> **Contributor:** "When the user edits a byte, do we change the **Original**?"
> **Maintainer:** "Never. An **Edit** adds a **Patch**; the **Original** is immutable. Everything you see — the hex grid, search, the **Analysis** — reads the **Patched view**, which is the Original overlaid with its Patches."
> **Contributor:** "And saving?"
> **Maintainer:** "Saving writes a **Patched copy** — a new file. We never overwrite the Original."
> **Contributor:** "In a **Diff**, is the 'use this side' button special?"
> **Maintainer:** "No. A **Merge** just copies one **Side**'s bytes into the other for a **Change**, realized as a **Patch** on the receiving Side — so undo works the same way. The old spot stays a **Merged region** so you can still see where it was."
> **Contributor:** "We detected the file as PEM-encoded X.509. Is that the **Format**?"
> **Maintainer:** "That's the **Kind** — detection's fine-grained, encoding-aware label. The **Format** is X.509; one **Analyzer** covers both the PEM and DER **Kinds**. The Analyzer turns the file into a **Structure** — the tree of **Nodes** and **Fields** you click to jump to bytes."

## Flagged ambiguities

- **"kind"** was used for two unrelated things: the file's **Kind** (detected classification) and an analysis **Node**'s element-category tag (e.g. `"packet"`). Resolved: **Kind** always means the file classification; a Node's element-category is its **category** and is not promoted to ubiquitous language.
