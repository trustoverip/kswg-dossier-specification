[[def: foreign-artifact-wrapper, foreign artifact wrapper, foreign artifact wrappers, foreign artifact acdc]]

~ A standard, issuee-less ACDC that gives a [[ref: foreign-artifact]] a cryptographic identity by attesting to its content digest and content type. The wrapper can be linked into a dossier's evidence graph like any other ACDC; a conforming wrapper MUST carry a `content_digest` (a CESR-encoded hash, preferably a bytewise or externalized SAID) and a `content_type`.
