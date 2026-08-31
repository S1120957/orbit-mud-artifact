# Double-blind checklist for this artifact

The venue uses **double-blind** review. Before exposing this artifact:

- [ ] Expose ONLY the anonymised mirror
      (https://anonymous.4open.science/r/orbit-mud-artifact-C4BB/).
- [ ] Keep any personal or institutional Git hosting of this repository
      **private** until acceptance. A public repository named after the system
      is discoverable by searching the system name and defeats anonymisation
      even if the paper never links to it.
- [ ] Confirm no commit history, author, or committer metadata is exposed by
      the mirror.
- [ ] Confirm the submitted PDF carries empty Title/Author properties
      (`pdfinfo submission.pdf`).

## Checks already performed on this tree (23 August 2026)
- No author names, institution names, emails, usernames, home directories,
  access tokens, or API keys in any source, config, log, or result file.
- No `.git` directory, no `.orig`/`.bak` files.
- Shipped PDFs: figure PDFs list only Matplotlib; manuscript PDFs have empty
  Title and Author fields.
- The only personal names anywhere are inside `paper-lncs/references.bib`, in
  the bibliography entry for the cited prior work `naeem2026towards`. That is a
  normal citation. The manuscript refers to it in the **third person**
  throughout ("prior work on symbiotic blockchain networks", "the off-chain
  aggregation principle established for..."), never as "our earlier work".
