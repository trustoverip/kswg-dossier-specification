[//]: # (Dossier Data Model {#sec:content})

## Dossier Data Model (Normative)

### Core Structure: The Dossier as an ACDC

A dossier MUST be a valid Authentic Chained Data Container (ACDC) as defined in the ACDC specification [2](https://trustoverip.github.io/kswg-acdc-specification/).

### The Role of the Issuer

The issuer of a dossier is the entity that curates the collection of [[ref: evidence]] and attests to its composition by digitally signing the container. The issuer's signature makes a specific, verifiable assertion: at the time of issuance, the collection of evidence referenced within the dossier is the exact collection the issuer intended to present. The issuer does not necessarily attest to the veracity of the claims within the evidence, but rather to the integrity and composition of the collection itself.

### The Edges Attribute: Linking to Evidence

The primary payload of a dossier is not a set of direct claims, but rather a graph of references to external [[ref: evidence]]. This graph is contained within an [[ref: edges]] block (`e`), as defined in the ACDC specification [2](https://trustoverip.github.io/kswg-acdc-specification/). This block MUST contain a JSON object where each key is a semantic label for an edge, and each value is an object describing the link to the external evidence.

A dossier MAY contain an unbounded number of edges, reflecting its core purpose of aggregating an arbitrary quantity and variety of evidence. The field names (keys) for these edges MAY be any valid JSON string, allowing issuers to provide semantically meaningful labels for the linked evidence (e.g.,
"vettingCredential", "forensicReport_01", "tnAllocationProof"), as demonstrated in the Verifiable Voice Protocol (VVP) specification.

### Base JSON-Schema Definition

To ensure a baseline of interoperability while preserving the flexibility required for diverse use cases, all dossiers MUST conform to a base JSON Schema. This specification defines the normative requirements for such a schema.

A compliant schema for a dossier:

* MUST be composed of an `allOf` array, of which one object is a `$ref` that references the base dossier schema by its SAID, and other objects add additional structure as desired. The `$ref` to the base dossier signals that the schema is for a dossier and should be processed using the dossier semantics defined in this spec. Example:

    ```json
    {
        "$schema": "[https://json-schema.org/draft/2020-12/schema](https://json-schema.org/draft/2020-12/schema)",
        "$id": "EOvMDBLnGaNHqfZgEnqnQO8lpzPQ5bRxC_RdoiniiuGz",
        "title": "Mortgage Creditworthiness Dossier",
        "description": "Evidence of a borrower's qualification for a mortgage.",
        "allOf": [
            { 
                "description": "reference to dossier base schema",
                "$ref": "ECqmlipYuqp8LA_7WdZGt_cKP9eK3hXtHRZGNgJ7NKEx"
            },
            {
                "type": "object",
                "description": "add properties unique to this dossier in next obj",
                "properties": {
                }
            }
        ]
    }
    ```

* MUST define fields within the ACDC `a` section for [[ref: proximate-metadata]].
* MUST use the ACDC `e` section ([[ref: edges]]) to bind the dossier to all evidenta, and MUST NOT place any evidenta in the `a` section.
* MAY include edges that are for traditional ACDC relationships but not for evidenta.
* SHOULD NOT include an issuee field.
* SHOULD set the `additionalProperties` keyword to true at the root level and for the edges object. This design choice lets issuers add arbitrary, application-specific edges without invalidating the dossier against the base schema.

This mandated flexibility has a direct consequence for implementers of verifier systems. A generic dossier verifier can be built to perform universal cryptographic validation—confirming signatures, SAIDs, and KEL consistency—for any dossier conforming to the base schema. However, such a generic verifier cannot be expected to understand the full semantics of every possible dossier. For instance, it can verify that an edge labeled "lunarPropertyDeed" is cryptographically linked, but it cannot know what that means or how to process it. Therefore, verification must be understood as a layered process. The first layer, cryptographic validation, is universal and defined by this specification. The second layer, semantic validation (e.g., "Does this dossier contain a valid TNAlloc credential for the phone number in question?"), is necessarily application-specific and requires context-dependent business logic. This separation allows the dossier format to be a universal building block for evidence aggregation across countless current and future use cases.

## Incorporating Evidence

A dossier's primary function is to serve as a container for references to
external evidence. This section defines the normative methods for incorporating
both ACDC-native and non-ACDC evidence formats.

### Referencing ACDC-Native Evidence

When a piece of evidence being included in a dossier is itself a valid ACDC
(for example, a vettingCredential or a TNAlloc credential as defined in VVP),
the corresponding edge in the dossier's edges block MUST reference that evidence
by its SAID and the SAID of its schema.

The value of the edge MUST be a JSON object containing at least the following
two keys:

- `n`: The SAID of the referenced ACDC. This provides a direct, tamper-evident
  link to the evidence artifact.
- `s`: The SAID of the schema to which the referenced ACDC conforms. This allows
  a verifier to correctly parse and interpret the evidence.

This pattern is exemplified by the sample dossier in the VVP specification.

### Referencing Non-ACDC Evidence

Not all evidence exists as a native ACDC. This specification recognizes two
distinct categories of non-ACDC evidence, each requiring a different treatment:
opaque file artifacts (photographs, audio recordings, PDFs, genomic data, and
any other binary or non-JSON content), and foreign credentials (data structures
from other verifiable credential ecosystems such as W3C Verifiable Credentials
or ISO mDLs). In both cases, the normatively RECOMMENDED approach is to wrap
the foreign material in a new ACDC before linking it into the dossier. Direct
reference to non-ACDC material without a wrapper is NOT RECOMMENDED, as it
places an untenable burden on the verifier to parse and validate an arbitrary
foreign format, understand its lifecycle, and locate its revocation mechanism.

#### Foreign Artifact Wrappers

Many forms of evidence are opaque file artifacts: photographs, audio and video
recordings, PDF documents, genomic data files, spreadsheets, and other binary
content. These formats cannot participate in authenticated data graphs using the
standard ACDC saidification algorithm, because that algorithm assumes JSON
content that can be canonicalized and rewritten.

The solution is to give the artifact a cryptographic identity using one of the
algorithms defined in the *Bytewise and Externalized SAIDs* specification [8](https://dhh1128.github.io/keri-tools),
and then issue a [[ref: foreign-artifact-wrapper, Foreign Artifact ACDC]] that attests to the [[ref: foreign-artifact, artifact]]'s identity
and provenance. The resulting wrapper is a standard ACDC and can be linked into
a dossier edge like any other evidentum.

Two algorithms are defined in [8](https://dhh1128.github.io/keri-tools) for saidifying opaque artifacts:

- The **bytewise SAID algorithm** (producing a **bSAID**) is appropriate for
  artifacts whose bytes can be rewritten after creation using native tooling —
  for example, a JPEG whose Exif metadata can be updated, or a Markdown file
  where a comment can be inserted. The artifact receives an insertion point
  containing the SAID, making the identifier intrinsic to the artifact's byte
  stream. A verifier can recover the SAID by scanning the raw bytes for the
  `SAID:` delimiter defined in [8](https://dhh1128.github.io/keri-tools).

- The **externalized SAID algorithm** (producing an **xSAID**) is appropriate
  for artifacts that cannot safely be rewritten after creation — for example,
  a compressed archive, an encrypted file, or a PDF whose cross-reference table
  would be invalidated by arbitrary byte modification. The SAID is carried in
  the filename under a constraint expressed inside the file content via the
  `XSAID:` delimiter defined in [8](https://dhh1128.github.io/keri-tools).

When neither algorithm is practical — for example, a data stream that was
captured without an insertion point — the `content_digest` field of the wrapper
MAY hold a plain CESR-encoded hash. In this case the integrity guarantee is
weaker: the hash cannot be discovered by inspecting the artifact itself, only
by consulting the wrapper.

In all cases, the CESR encoding of `content_digest` is self-describing: the
primitive code identifies the hash algorithm, so no separate algorithm field
is required.

A conforming [[ref: foreign-artifact-wrapper, Foreign Artifact wrapper]] MUST satisfy the following minimum
requirements:

1. It MUST be a valid ACDC with no issuee.
2. Its `a` section MUST contain a `content_digest` field holding a
   CESR-encoded hash, and a `content_type` field holding an IANA MIME type
   string.
3. The `content_digest` SHOULD be a bSAID or xSAID as defined in [8](https://dhh1128.github.io/keri-tools).

A reference schema and example for a Foreign Artifact ACDC are published
separately at [9](https://dhh1128.github.io/keri-tools). Implementers MAY define specialized schemas that
extend the reference schema for domain-specific artifact types, provided the
minimum requirements above are satisfied.

#### Bridging from Foreign Credential Ecosystems

Where the non-ACDC material is itself a verifiable credential from another
ecosystem — such as a W3C Verifiable Credential or an ISO mDL — a different
wrapping strategy applies. In this case a designated [[ref: bridging-party, bridging party]] obtains
the foreign credential, verifies it according to its native rules and policies,
and issues a new ACDC — the bridge wrapper — that attests: "I, the bridging
party, successfully verified the attached foreign credential on date X according
to policy Y." The [[ref: bridge-wrapper, bridge wrapper]] is then linked into the dossier using the
standard ACDC-native mechanism.

This pattern transforms the problem of verifying a foreign format into the
problem of trusting the attestation of the bridging party. That standardizes
the verification process for the dossier's consumer, but verifiers must keep
two caveats in mind. First, trust in the wrapped evidence depends on the
reputation, security practices, and verification policies of the bridging
party. Second, the revocation lifecycles of the original foreign credential
and of the bridge wrapper are decoupled unless a specific governance framework
explicitly links them.

## The Operational Lifecycle: Creation, Evolution, and Verification

The dossier is a persistent, evolving data artifact with a distinct lifecycle encompassing curation, iterative assembly, state management, citation, and verification.

### Curation: Assembling and Signing the Dossier

Curation is the process of creating a dossier. This phase is typically performed in advance of any real-time transaction and involves the assembly and attestation of the evidence collection.

The normative steps for dossier curation are as follows:

1. Evidence acquisition: The entity intending to issue the dossier first acquires the necessary evidence from their respective authoritative sources. For example, a business might obtain a legal entity vetting credential from a qualified issuer, a telephone number allocation credential from its carrier, and a brand credential from a brand vetter.

2. Assembly: The issuer or [[ref: collector]] constructs the dossier ACDC data structure. This involves creating an edges block and populating it with named links that point to each acquired evidence artifact, as described in Section 3.

3. Iterative assembly and versioning: Some dossiers are static, but with others, as new evidence is collected or the status of investigation changes, the dossier evolves. To support this, [[ref: collector]]s MAY issue new versions of a dossier. A new version MUST be a valid ACDC that links to the previous version via a prev [[ref: edge]] or a schema-specific equivalent. This creates a verifiable chain of the dossier's history, allowing verifiers to traverse back through the lineage of the evidence collection.

4. Issuance initiation: For single-issuer dossiers, the [[ref: collector]] signs the fully assembled dossier ACDC. For joint issuance, the [[ref: collector]] provides the drafted ACDC to a [[ref: coordinator]]. The [[ref: coordinator]] then coordinates the signing or anchoring process among the designated members.

5. Signing and anchoring: The [[ref: collector]] or [[ref: finalizer]] uses the private keys associated with a KERI AID to sign the dossier. This act creates a non-repudiable attestation to the dossier's content. The issuance event is then anchored in a key event log (KEL), providing a permanent record. In joint issuance, this anchor may be distributed across several KELs or consolidated in a finalization event.

6. Publication: The issuer or [[ref: coordinator]] publishes the signed dossier ACDC at a stable, publicly resolvable location, typically one or more HTTP URLs. This allows authorized verifiers to fetch the dossier when it is cited.

### State Management and Metadata Overlays

For dossiers used in procedural contexts (e.g., legal proceedings, insurance adjustments), the mere existence of evidence is insufficient; its status relative to the procedure matters. An artifact may be "marked for identification," "admitted," "objected to," or "stricken." Because ACDCs are immutable, an issuer cannot simply modify the metadata of an existing [[ref: edge]].

To manage these state transitions, dossiers MUST use **Annotation Edges**. An annotation edge is an edge in a new version of the dossier that points to an artifact (or an edge) in a previous version. The payload of the annotation edge carries the new state or ruling. For example, a "Court Case Dossier v2" might contain an edge labeled `ruling_101` that points to the SAID of `exhibit_A` (from v1) with the attribute `status: "admitted"`. Verifiers MUST process the dossier by traversing the graph to resolve the "effective state" of each piece of evidence, applying the latest annotations found in the chain.

### Temporal Pinning

Many dossiers require evidence of dynamic states, such as a bank balance, a credit score, or a current employment status. Direct links to live APIs are unverifiable in a static context. To include dynamic data, issuers MUST use **Temporal Pinning**.

This process requires the [[ref: assembler]] (or a trusted "[[ref: oracle]]" service) to:
1. Observe the dynamic state at a specific instant (`Time T`).
2. Wrap that observation in a signed ACDC (an "[[ref: observation-attestation, Observation Attestation]]").
3. Anchor that ACDC in a KEL.

The dossier then links to this static, timestamped Observation Attestation. This effectively "freezes" the data stream at a specific block height, allowing the dossier to assert, "The borrower had $50,000 in this account at the exact moment this dossier was assembled," rather than "The borrower has $50,000 now."

### Citation: Referencing the Dossier in Protocols

Because dossiers are designed to be stable, long-lived, and potentially large data structures, they are generally not transmitted in their entirety within real-time communication protocols. Instead, they are cited.

A [[ref: citation]] is a reference that allows a verifier to locate and retrieve the full dossier. The normative requirement for a dossier citation is that it MUST be a resolvable identifier that enables a verifier to fetch the complete and unmodified dossier ACDC. The canonical implementation of this is the Out-of-Band Invitation (OOBI) URL used in the evd (evidence) claim of a VVP passport. An OOBI is a specialized URL that points to a resource serving the ACDC and its associated KERI proofs.

### Verification: Algorithm for Validation

The verification process for a dossier requires a citation and a [[ref: reference-time, referenceTime]] as inputs. To support joint issuance, the algorithm follows these steps:

1. Fetch dossier: resolve the citation to retrieve the dossier ACDC.

2. Validate dossier integrity: calculate the SAID of the retrieved data and ensure it matches the expected SAID from the citation.

3. Determine issuance model: inspect the edges block for the FIN [[ref: operator]] or m-ary M operator.

4. Validate signatures and anchors:
   a. If the FIN operator is present, locate the finalization event in the primary KEL. Verify that the event contains the required threshold-satisfying signatures or seals.
   b. If the FIN operator is absent but an M operator is present, identify the member AIDs defined in the threshold group. Fetch the individual KEL for each member and verify that a valid seal to the dossier SAID exists in each KEL. Confirm that the total weight of verified members meets the threshold defined in the M operator.
   c. For standard dossiers with a single issuer, retrieve the issuer KEL and verify the signature against the public keys authoritative at the referenceTime.

5. Recursive graph traversal: for each named edge in the edges block, fetch the referenced artifact and perform this validation algorithm recursively.

6. Check revocation status: for the dossier and every node in the evidence graph, consult the relevant KELs or status registries for revocation events effective at the referenceTime.

7. Apply semantic rules: apply application-specific policy rules once cryptographic validation is complete.

### The Attributes Section: Proximate Metadata

A dossier differs from an ordinary ACDC credential in how it uses the attributes
(`a`) section. In a conventional credential, the `a` section carries the issuer's
claims about a subject — the substance of what is being asserted. In a dossier,
the substance of the assertion is the evidence graph, which enters the dossier
exclusively through edges. The `a` section MUST NOT be used to carry primary
evidence. Instead, it is reserved for proximate metadata: facts about the dossier
itself that the issuer wishes to attest directly as part of the act of issuance.

The distinction can be illustrated concretely. An insurance adjuster assembling a
dossier about a car crash would include photographs of the vehicles, a diagram of
the intersection, and witness statements as edges — these are the evidence. The
adjuster's name, the case number, the date the dossier was assembled, and the
governance framework under which it was produced are metadata about the dossier,
and belong in the `a` section.

This separation preserves the architectural integrity of the dossier model: edges
are the mechanism for cryptographically linking to external, independently verifiable
artifacts, while the `a` section provides the context and provenance that frames
the evidence collection as a whole.

#### Standard Proximate Metadata Fields

The following fields are defined for use in the `a` section of a dossier. All are
optional unless a governing schema requires otherwise. Implementers MAY define
additional fields appropriate to their domain.

- **`assembly_dt`**: An ISO 8601 timestamp recording when the dossier was assembled.
  This is distinct from the issuance date recorded in the ACDC envelope, which may
  differ if the dossier was finalized and signed at a later time.

- **`assembler`**: The AID or human-readable name of the entity that curated the
  evidence collection. This field is most useful when the assembler differs from
  the issuer — for example, when a staff member compiles the evidence and a senior
  officer issues the dossier.

- **`purpose`**: A brief, human-readable statement of why the dossier was assembled
  and what decisions it is intended to support. Example: `"Document evidence of
  loss for claim #A-2047 per policy terms."` This field is not intended to be
  machine-interpreted; it serves as a plain-language summary for human reviewers.

- **`ref`**: An external reference identifier, such as a case number, docket number,
  or transaction ID, that links the dossier to a record in an external system. This
  field is intentionally untyped; its meaning is determined by the governance context.

- **`gov`**: A SAID or URI referencing the governance framework, policy
  document, or rulebook under which the dossier was assembled. This allows verifiers
  to evaluate not just the cryptographic integrity of the dossier but the procedural
  legitimacy of its curation.
  
- **`evt_dt`**: An ISO 8601 timestamp of the event that the dossier documents
  — for example, the time of a crash, crime, filing, or transaction. This is
  distinct from `assembly_dt`, which records when the evidence collection was
  curated. In many cases these will differ significantly: an NTSB investigation
  may be assembled months after the accident it documents.

- **`evt_loc`**: A human-readable or structured description of where
  the event or subject matter occurred. No single location format is mandated,
  as appropriate precision varies widely by domain: a GPS coordinate pair is
  suitable for a crash site, while a court venue is better expressed as a name
  and jurisdiction code. Implementers operating in domains with established
  location standards SHOULD follow those standards (e.g., ISO 6709 for
  geographic coordinates).

- **`jur`**: The legal or regulatory jurisdiction within which the
  dossier's subject matter falls, or under whose authority the evidence was
  collected. This identifies a legal/regulatory jurisdiction, not a geographic
  location. Expressed as an ISO 3166-1 alpha-2 country code, optionally
  extended with an ISO 3166-2 region or province code (e.g., `US-TX`, `FR`,
  `CA-ON`). Where multiple jurisdictions apply, this field MAY be an array.

- **`cls`**: A string identifying the type or category of matter
  the dossier documents. The value space is domain-dependent: a law enforcement
  dossier might use a statute reference or offense code; an NTSB dossier might
  use an event type from the NTSB taxonomy; a court dossier might use a case
  type such as `civil`, `criminal`, or `appellate`. Implementers SHOULD
  reference a controlled vocabulary appropriate to their domain, and MAY
  express this as a URI identifying the vocabulary entry.

- **`phase`**: A string indicating the procedural maturity of the dossier at
  the time of issuance — for example, `preliminary`, `factual`, or `final` in
  an NTSB investigation; `investigation`, `adjudication`, or `closed` in a law
  enforcement context. This field is distinct from the revocation or annotation
  state of individual evidence items, which is managed through annotation edges.
  When a dossier transitions between phases, a new version SHOULD be issued
  rather than the existing dossier modified in place.

- **`gov_rules`**: A SAID or URI identifying a specific protocol,
  standard, or ruleset that governed the collection of evidence in this dossier
  — for example, a forensic collection protocol, the Federal Rules of Evidence,
  or NTSB investigation procedures. This field is more specific than `gov`,
  which identifies the framework under which the dossier itself was assembled.
  Both fields MAY be present simultaneously: `gov` describes who is
  overseeing the dossier, while `gov_rules` describes what procedural
  constraints applied to the underlying investigation.
  
## Joint issuance
A dossier may be assembled and signed by a single party. For example, an artist who wishes to collect cryptographic evidence of their creations may do so as a solo activity. However, many dossiers snapshot evidence contributions from multiple parties, and so represent a group work product that needs an aggregate approval mechanism. In such cases, signing the ACDC that references all the individual pieces of evidence is managed with joint issuance.

### Logic
Joint issuance is best understood not as a single, uniform approach to approval, but as a family or style of approval strategies. It maps onto the problem domain of coordinated control in multi-agent systems, which has been formally studied in robotics, AI, military science, and similar fields. Three variants of cooperative control are regularly mentioned in the literature [5](https://doi.org/10.1109/87.960341) [6](https://doi.org/10.1016/j.automatica.2014.10.022) [7](https://doi.org/10.1109/TAC.2004.834433):

* leader-follower 
* behavior-based control
* virtual structures

A dossier can be approved using any of these variants, and this specification normatively describes success using primitives relevant to all three. The description below focuses on the leader-follower approach because it is the simplest to understand and lends itself most easily to deterministic guarantees. Whatever cooperative control mechanism is chosen, the process involves asynchronous signing that converges on a common goal, possibly over a significant span of time. Unlike group multisig, which requires synchronous agreement on key event log (KEL) sequence numbers, joint issuance relies on logic within the ACDC layer. This lets members contribute signatures or seals to a dossier at different times and via different channels without immediate impact on a shared KEL.

The validity of a jointly issued dossier is determined by satisfying a [[ref: threshold-operator, threshold operator]] within its [[ref: edge]] graph. Because the logic is decoupled from key management, issuance and verification have more flexibility.

### Leader-follower roles
When joint issuance is coordinated with a leader-follower strategy, three distinct roles emerge, that may be performed by the same or different entities:

* Collector: the entity that assembles the evidence artifacts and defines the initial dossier structure.
* Coordinator: the entity that, once collection is finished, initiates the issuance action and distributes the candidate dossier for endorsement.
* Finalizer: any entity that, upon observing that an issuance threshold is met, submits a finalization event to a KEL.

### Threshold mechanics
A joint issuance MUST satisfy an m-ary threshold operator defined in the edge section of the dossier ACDC. A schema MAY define the required threshold and the set of possible signers. Alternatively, a schema MAY defer these definitions to the dossier instance, allowing the threshold rules to be actualized only when the issuance is proposed.

### New operators for joint issuance
The following operators are defined to support the logic of joint issuance within the edges block:

* `M`: a [[ref: threshold operator]] that declares that issuance is accomplished by satisfying an endorser count. This number MUST be expressed via a corresponding field on the edge, `m`. The presence of this operator triggers a requirement that the set of corresponding signers MUST be represented in the edges of the edge group to which the operator is attached. The `M` operator also allows valid *potential* signers (as opposed to *actual* signers in the edge) to be enumerated in advance. When they are, the enumeration MUST occur in the attributes (root `a` object) section of the ACDC, and MUST consist of an array of AIDs. If a field named `mgrp` appears as a property on the same edge as `M`, it MUST name the field in the attributes section where this enumeration occurs. If `mgrp` does not appear as a property on `M`'s edge group, then the enumeration of potential signers MUST be given in a field named `mgrp` in the attributes section. The `M` operator with enumerated potential signers thus embodies an *m of n* approval pattern: `m` supplies the threshold, and the cardinality of potential signers enumerated in `mgrp` provides the logical upper bound *n*. An example is a judicial decision jointly issued by *m* of *n* justices, where the AIDs of the judges are enumerated and *m* constitutes a majority. An `M` operator that does not enumerate valid potential signers MAY instead be combined with the `Q` operator to model an unbounded number of potential signers who must still be qualified in some way; see below.
* `RM`: a [[ref: revocation operator]] that declares that revocation is accomplished by satisfying a revoker count. `RM` has parallel semantics to `M`, but its corresponding numeric field on the edge is `rm`, and its potential revokers are enumerated in an `rmgrp` field in the attributes section, or in an attribute field with the name specified in the `rmgrp` field on the edge. This flexibility allows the set of revokers to be identical to the set of endorsers used for `M`, to overlap that set, or to be entirely disjoint, and allows the threshold for revocation to differ from the threshold for issuance.
* `Q`: A [[ref: qualification-operator, qualification operator]] that determines a standard of proof that signers MUST meet. When this operator is present, the edge MUST also contain a `qschema` property that describes the proof that must exist, plus a `qev` array that enumerates edges of evidence presented by each signer as proof of qualification.
* `FIN`: a [[ref: finalization operator]] that signals whether a verifier should expect a finalization event in a KEL. Recording a finalization event in the KEL allows verifiers to predict where aggregate evidence may be collected for easy review. Without it, a verifier must collect evidence of joint issuance signatures from disparate locations.

### Finalization
A [[ref: coordinator]] MAY choose to finalize a joint issuance to assist verifiers that do not perform recursive graph traversal.

1. Satisfaction: a [[ref: finalizer]] observes that a sufficient number of signatures or seals have been gathered to meet the threshold.
2. Allocation: the [[ref: finalizer]] allocates the next sequence number in the relevant KEL, which is typically a group AID.
3. Anchoring: the [[ref: finalizer]] attaches the threshold-satisfying proofs to a KEL event and submits it for witnessing.

If a finalization event is present, a verifier SHOULD use it as the definitive proof of issuance. If absent, a verifier MUST poll the individual KELs of all possible participants to determine whether the threshold has been met.

### Revocation
Revocation logic in a joint issuance may be defined independently of issuance logic.

* Default: if no separate revocation rule is defined, the threshold required to revoke a dossier is identical to the threshold required to issue it.
* Asymmetric thresholds: a dossier may specify different operators for creation and revocation. For example, a dossier may require a majority for issuance but allow a single administrative AID to perform a revocation.

## Dossiers and Derivative References

A dossier is intentionally heavy. It may be assembled once and signed jointly by many parties, may carry a graph of arbitrarily many evidence items, and may require a verifier to fetch and validate every node in that graph against multiple KELs. This cost is acceptable because a dossier is designed for reuse: curation happens once, and the resulting artifact serves as an authoritative reference for many later transactions, verifiers, and decisions.

In transactional protocols, however, the dossier itself is rarely transmitted. Sending a multi-kilobyte ACDC and requiring full recursive verification on every call is impractical for real-time use cases such as a phone call, a checkout step, or an API request. Instead, the transactional payload carries a lightweight [[ref: derivative]] that references the dossier. The dossier remains the primary, persistent artifact; the derivative is short-lived, single-purpose, and cheap to produce and validate.

This specification recognizes two derivative forms:

- **Citation.** A resolvable identifier (canonically an OOBI URL) that lets a verifier fetch the full dossier and run the verification algorithm. Citations are defined under *Citation: Referencing the Dossier in Protocols* above.

- **Token.** A short-lived signed object that carries enough context for an immediate verification decision and embeds the dossier SAID as an evidence pointer. A minimal token might take this shape:

    ```json
    {
        "iss": "EJ7q...kT9a",
        "iat": 1747843200,
        "exp": 1747843260,
        "aud": "https://verifier.example/api",
        "nonce": "f3c9...",
        "evd": "E46p...5fa9"
    }
    ```

    with a signature over the canonical encoding. The token asserts that, between `iat` and `exp`, its bearer is acting under the authority of the dossier whose SAID is given in `evd`. A verifier with a cached, previously validated copy of the dossier MAY accept the token without re-traversing the evidence graph. A verifier that requires fresh assurance dereferences `evd`, runs the full verification algorithm, and caches the result for subsequent presentations.

A derivative MUST cryptographically bind to the dossier it references — minimally by including the dossier SAID under the derivative's signature. A derivative MUST NOT be treated as independent evidence: its authority derives entirely from the dossier, and its trust value collapses to that of the dossier alone if the binding cannot be checked.

Derivatives inherit the dossier's revocation lifecycle. When a verifier evaluates a derivative, it MUST consult the dossier's revocation state effective at the verification time, not at the time the derivative was issued. A token issued before its referenced dossier was revoked is not valid after the revocation event, even if the token's own `exp` has not yet passed.

This split between dossier and derivative separates two questions that are conflated in conventional bearer credentials:

- *What was attested, and by whom?* This lives in the dossier and is curated once, then amortized across many transactions.
- *Who is presenting it now, in what session, under what immediate constraints?* This lives in the derivative and is bound to the specific transaction through ephemeral fields (`iat`, `exp`, `aud`, `nonce`).

Implementers MAY define additional derivative forms — for example, a summary that exposes a redacted subset of the dossier's proximate metadata for human review, or a blinded proof that attests dossier validity without revealing its SAID (see *Mitigation Strategies for Unwanted Correlation* below). Any such form is subject to the binding and revocation requirements above. Replay protections for transactional citation messages are addressed under *Replay Attack Mitigation in Citation Protocols* below.

## Security Considerations

### Integrity and Non-Repudiation Via KERI

The security of the dossier model is founded on the cryptographic primitives provided by KERI and ACDC.

Integrity: Self-addressing identifiers (SAIDs) guarantee the integrity of the dossier and all ACDC-native evidence within its graph. A SAID is a cryptographic hash of an object's canonical content. Any modification to the data results in a different SAID, making tampering immediately evident.

Non-repudiation: Digital signatures make the act of issuing a dossier non-repudiable. These signatures are cryptographically anchored in a key event log (KEL), which serves as a permanent, publicly auditable, and tamper-evident log of all significant actions. In joint issuance, the collective anchors of all participating members in their respective KELs provide non-repudiation. A finalization event, if used, provides a single cryptographic record of this consensus.

### Replay Attack Mitigation in Citation Protocols

The dossier itself is a stable, long-lived artifact designed for reuse. As such, the primary risk of replay attacks exists at the level of the protocol that cites it. An attacker could capture a valid citation message and re-submit it in a different context.

To mitigate this, any protocol that cites a dossier MUST incorporate ephemeral, context-specific data into the payload that is cryptographically signed. This data MUST bind the citation to a unique transaction using timestamps to create a narrow window of validity, originator and destination identifiers, and unique nonces to prevent identical replays.

### Verifier Trust and Root of Trust Management

The dossier model operates on a decentralized root of trust. A verifier does not rely on a single authority but makes explicit trust decisions about a plurality of evidence issuers. In joint issuance, this trust is distributed across the member AIDs defined in the threshold.

The foundation of this trust is the KERI witness infrastructure. Witnesses are independent services that act as notaries for an AID's KEL. By requiring an issuer to report its key events to a set of witnesses, the system gains high availability and duplicity detection. Verifiers SHOULD consult multiple witnesses to ensure they have a consistent and complete view of an issuer's KEL, thereby protecting against duplicity and compromise.

### Long-term Auditability and Historical Analysis

The KERI-based dossier ecosystem supports long-lived auditing. Because KELs provide a complete, verifiable, and sequenced history of an identifier's key state, a verifier can perform validation for any arbitrary point in the past. 

This capability is critical for use cases involving compliance and legal discovery. An auditor can determine if a dossier and its entire evidence graph were valid at the time of a transaction, based on the key states and revocation information known at that moment. This provides non-repudiable historical accountability.

## Privacy Considerations

### Graduated Disclosure Mechanism

Dossiers MAY support privacy-preserving disclosure of their contents through the graduated disclosure mechanism inherent to the ACDC specification. An ACDC is a hierarchical JSON object, and its SAID is computed recursively: the hash of a parent object is derived from its scalar values and the SAIDs of its child objects.

This structure means that any child object within an ACDC can be replaced by its SAID without altering the SAID of the parent object and without invalidating the digital signature on the entire container. This allows the holder or issuer of a dossier to generate redacted versions of the ACDC. These versions selectively hide sensitive information while remaining cryptographically verifiable. In joint issuance, redaction does not affect the validity of member seals anchored in KELs, as those seals point to the immutable SAID of the root dossier.

### Analysis of Data Correlation Vectors

Even with the use of graduated disclosure, verifiers may be able to correlate activity across multiple transactions by observing persistent identifiers. The primary correlation vectors in a dossier-based protocol are:

* Dossier SAID: the SAID of the dossier itself is a unique and persistent identifier for that specific evidence collection.
* Citation signer AID: the AID of the entity signing the real-time citation message can be used to link all messages signed by that same identifier.
* Explicit brand information: any unredacted brand information is an intentional correlator.

### Mitigation Strategies for Unwanted Correlation

Where privacy is a requirement, implementers SHOULD use strategies to mitigate these correlation vectors.

For the citation signer AID: the AID used for signing transactional messages can be rotated frequently without affecting the long-lived AID of the dossier issuer. A service provider signing on behalf of many clients can also maintain a pool of AIDs to provide herd privacy and break correlation.

For the dossier SAID: to break the link between a transaction and a persistent dossier SAID, a trusted third party or blinding service MAY be used. This service can verify an original dossier and then issue a new, short-lived, derivative dossier. This derivative dossier attests to the validity of the original without revealing its SAID to the end verifier.

### Contractually Protected Disclosure

Technical privacy mechanisms can be augmented with legal and contractual controls. A server hosting a dossier MAY be configured to enforce access control policies. For example, it could serve a redacted, privacy-preserving version of a dossier to any anonymous request but require a cryptographically signed request to access a more expanded version. The act of signing the request can be tied to the verifier's agreement to terms regarding data privacy, creating a verifiable audit trail of who accessed sensitive information.

## Use Cases and Architectural Patterns

The following use cases illustrate distinct architectural patterns for deploying dossiers. Each profile highlights a different combination of grouping strategies, state management, and trust delegation, demonstrating the dossier's flexibility across diverse domains.

### Verifiable Voice Protocol (VVP): The Compositional Dossier

The Verifiable Voice Protocol (VVP) represents the **Compositional Dossier** pattern. Here, the primary goal is not to tell a story or trace a history, but to assemble a valid "permission slip" from independent authorities.

* **Goal:** Prove the right to engage in a high-trust activity (making a call).
* **Key Concept: Distributed Root of Trust.** In this pattern, the dossier assembler (the Accountable Party) does not generate the evidence. Instead, they act as a [[ref: collector]], bundling credentials issued by distinct, domain-specific roots of trust:
    * **Legal Identity:** Vetted by a Legal Entity Identifier (LEI) issuer.
    * **Resource Authority:** Telephone number usage vetted by a telecom carrier or regulator.
    * **Brand Rights:** Vetted by a trademark steward.
* **Verification Logic:** The verifier validates the dossier by recursively checking the issuers of the edge credentials. Trust is derived from the leaf nodes (the authorities), not merely from the dossier issuer. This pattern is ideal for access control, licensing, and regulatory compliance.

### Law Enforcement and Adjudication: The Procedural Dossier

This profile illustrates the **Procedural Dossier** pattern, which manages the complex lifecycle of evidence from field collection through courtroom adjudication. It extends the "Crime Scene" concept to handle the adversarial nature of legal proceedings.

* **Goal:** Maintain a tamper-evident Chain of Custody while allowing for the procedural evolution of evidence status.
* **Key Concept: Lifecycle of Evidence and State Transitions.**
    * **Phase 1 (Investigation):** The dossier serves as an immutable "bag" of collected artifacts (photos, DNA reports). The focus is on *completeness* and *provenance*.
    * **Phase 2 (Adjudication):** As the case moves to trial, evidence undergoes state changes. An artifact may be `Marked`, `Offered`, `Admitted`, or `Stricken`.
* **Mechanism:** This pattern employs **Annotation Edges** (see Section 10.2). To "strike" a piece of evidence, the Clerk of the Court issues a new dossier version containing an edge that targets the original evidence's SAID and applies a `status: "stricken"` attribute. This preserves the original artifact (essential for appeals) while explicitly excluding it from the current "effective" body of facts.

### Investigative Journalism: The Redacted Dossier

This profile demonstrates the **Redacted Dossier** pattern, designed to reconcile the conflict between the need for public verification and the obligation to protect confidential sources.

* **Goal:** Prove the existence and provenance of source material without revealing the source's identity.
* **Key Concept: The Precursor Link.** This pattern uses the Cross-File Association (CFA) concept of "precursor" relationships.
    * **The Private Graph:** The journalist holds a "Source Asset" (e.g., an unredacted recording of a whistleblower).
    * **The Public Graph:** The journalist publishes a "Redacted Asset" (e.g., a transcript with names removed).
* **Mechanism:** The public dossier links to the Redacted Asset. Internally, the Redacted Asset is cryptographically linked to the Source Asset via a "blinded" edge—typically a hash of the original file. This allows the journalist to prove, at a future date (e.g., declassification), that the redacted text was indeed derived from the specific original recording, without having exposed the source during the investigation.

### Mortgage Qualification: The Snapshot Dossier

The Mortgage Qualification profile illustrates the **Snapshot Dossier** pattern, which addresses the challenge of verifying dynamic, volatile data such as bank balances or credit scores.

* **Goal:** Prove the state of a changing system at a specific point in time.
* **Key Concept: Temporal Pinning.** A dossier cannot simply link to a bank's API, as the balance changes. It must link to a static artifact.
* **Mechanism:** This pattern employs the **[[ref: oracle, Oracle]]** or **[[ref: oracle, Observer]]** role. The assembler (or a trusted third-party service) queries the dynamic data source at `Time T`. This observation is then wrapped in a signed ACDC (an "Observation Attestation") that effectively says, "I observed Account X having Balance Y at Block Height Z." The dossier links to this static attestation. This converts a stream of data into a verifiable snapshot, allowing a loan officer to verify "Funds Available" at the exact moment of the application.

### Clinical Trials: The Predicate Dossier

This profile introduces the **Predicate Dossier** pattern, essential for environments with strict privacy regulations (e.g., HIPAA, GDPR) where raw data cannot be shared.

* **Goal:** Prove eligibility or compliance without disclosing the underlying sensitive data.
* **Key Concept: Zero-Knowledge Predicates.**
* **Mechanism:** Instead of linking to a raw evidence file (e.g., `blood_test_results.pdf`), the dossier links to a **Predicate Edge**. This edge points to a Zero-Knowledge Proof (ZKP) or a derived cryptographic claim generated from the raw data.
    * *Example:* The dossier asserts `inclusion_criteria_met: true`. The evidence is a ZKP proving that "Subject Age > 18 AND HIV_Status == Positive" without revealing the subject's birthdate or specific medical markers.
* **Verification:** The verifier validates the cryptographic proof rather than parsing the document, enabling high-assurance compliance without data leakage.

### The Petition: The Open-Endorsement Dossier

This profile demonstrates the **Open-Endorsement Dossier** pattern, designed for cases where the set of participants is large or cannot be fully enumerated at the start of the curation process.

- **Goal:** Collect a threshold of endorsements from a distributed and potentially dynamic set of signers.
- **Key Concept: Asynchronous Threshold Satisfaction.** Unlike a standard multisig group that requires tight coordination among a fixed set of peers, this pattern allows any AID that satisfies the criteria defined in the dossier schema to contribute an endorsement.
- **Mechanism:** The coordinator initiates the dossier and distributes the candidate ACDC. Participants signify their agreement by anchoring a seal to the dossier SAID in their individual KELs. The dossier uses the `M` operator (optionally combined with `Q`) to define the conditions for validity, such as a specific count of qualified, unique endorsements.
- **Verification:** A verifier confirms the dossier is valid by observing that the required number of individual KELs contain the necessary seals. The coordinator may choose to finalize the dossier once the target count is reached, simplifying this check for third parties.

[//]: # (\newpage)

[//]: # (\makebibliography)

## Bibliography

[1]. [KERI — Key Event Receipt Infrastructure](https://trustoverip.github.io/kswg-keri-specification/)

[2]. [ACDC — Authentic Chained Data Containers](https://trustoverip.github.io/kswg-acdc-specification/)

[3]. [CESR — Composable Event Streaming Representation](https://trustoverip.github.io/kswg-cesr-specification/)

[4]. [Verifiable Voice Protocol](https://www.ietf.org/archive/id/draft-hardman-verifiable-voice-protocol-05.html)

[5]. Beard, R. W., Lawton, J., and Hadaegh, F. Y. 2001. A coordination architecture for spacecraft formation control. IEEE Transactions on Control Systems Technology 9, 6 (November 2001), 777–790. [https://doi.org/10.1109/87.960341](https://doi.org/10.1109/87.960341)

[6]. Oh, K.-K., Park, M.-C., and Ahn, H.-S. 2015. A survey of multi-agent formation control. Automatica 53 (March 2015), 424–440. [https://doi.org/10.1016/j.automatica.2014.10.022](https://doi.org/10.1016/j.automatica.2014.10.022)

[7]. Fax, J. A., and Murray, R. M. 2004. Information flow and cooperative control of vehicle formations. IEEE Transactions on Automatic Control 49, 9 (September 2004), 1465–1476. [https://doi.org/10.1109/TAC.2004.834433](https://doi.org/10.1109/TAC.2004.834433)

[8]. Hardman, D. ["Bytewise and Externalized SAIDs"](https://dhh1128.github.io/keri-tools). 2024.

[9]. Hardman, D. ["Foreign Artifact Credential"](https://dhh1128.github.io/keri-tools).

[10]. Sporny, M., Longley, D., Sabadello, M., Reed, D., Steele, O., and Allen, C., Eds. ["Verifiable Credentials Data Model v2.0"](https://www.w3.org/TR/vc-data-model-2.0/). W3C Recommendation.
