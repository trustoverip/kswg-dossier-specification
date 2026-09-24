## Dossier Data Model (Normative)

### Core Structure: The Dossier as an ACDC

A dossier MUST be a valid Authentic Chained Data Container (ACDC) as defined in the ACDC specification [[2]].

### How a Dossier Is Issued: Anchoring, Not Attached Signatures

Terminology in this area is easy to get wrong, and the wrong reading has real
consequences for implementers, so this specification states the mechanism once
here and relies on it throughout.

A dossier is not a signed document. The issuer does not compute a signature
over the dossier ACDC and attach that signature to it as proof of authenticity,
which is what "signing a credential" means in most other verifiable credential
ecosystems. Instead:

1. The assembled dossier ACDC is saidified, yielding its SAID.
2. The issuer constructs a seal containing that SAID.
3. The issuer anchors the seal in an append-only verifiable log — either
   directly in the key event log (KEL) of the issuer's AID, or in a transaction
   event log (TEL) for the dossier whose own events are in turn anchored in
   that KEL.
4. The key event carrying the anchor is signed with the keys authoritative for
   the issuer's AID at that point in the log.

The signature exists on the anchoring key event, not on the dossier. What binds
the issuer to the dossier is the anchor: a commitment to the dossier's SAID,
placed in a log that is append-only, duplicity-evident, and witnessed.

This indirection is what lets a dossier survive the verification horizons
described under *Evidence Lifespans and Verification Timing*. An attached
signature can be checked only against the key that produced it, and nothing in
the signature itself establishes when it was made; once that key is rotated or
compromised, a verifier has no way to distinguish a signature made while the
key was authoritative from one made afterward. An anchor is evaluated against
the key state the KEL shows was authoritative at the position where the
anchoring event sits, so it stays verifiable across any number of later
rotations. Because a dossier is expected to be verified years or decades after
issuance by parties who cannot reach the issuer, anchoring is the only
mechanism that satisfies the requirement.

Accordingly, this specification uses these terms precisely:

- To **anchor** an artifact is to commit its SAID into an append-only
  verifiable log by placing a seal containing that SAID in an event of that
  log. An **anchored** artifact therefore carries a non-repudiable and
  perpetually verifiable commitment from the AID that controls the log.
- **Signed** means bearing an attached digital signature computed over an
  artifact's own bytes. In this specification, key events are signed, and so
  are the short-lived transactional objects described under *Dossiers and
  Derivative References*. Dossiers, endorsements, and other ACDCs are anchored.
- **Authenticated** is used where an obligation is satisfied by either
  mechanism — for example, the requirement that a candidate's refusal be
  attributable to that candidate.

#### Ephemeral Dossiers With Attached Signatures

One narrow exception exists. A dossier that lives only for the duration of a
single interaction, and that will never be verified after the issuer's next key
rotation, MAY be authenticated by an attached signature over the dossier ACDC
rather than by an anchor.

An implementation that takes this option accepts three consequences:

- The dossier ceases to be verifiable once the signing key is no longer part of
  the current key state for the issuer's AID, because nothing establishes when
  the signature was made.
- The issuer's commitment becomes repudiable in practice. Absent a log entry,
  there is no duplicity-evident record that the issuer ever made it.
- Verification at a [[ref: reference-time, referenceTime]] other than the
  present is not possible.

Because these consequences remove the properties that motivate the dossier
model in the first place, an attached signature is NOT RECOMMENDED for any
dossier that is published, cited, cached, or otherwise expected to outlive the
transaction that produced it. A verifier MUST NOT treat an attached signature
as equivalent to an anchor when evaluating a dossier as of any referenceTime
other than the present.

### The Role of the Issuer

The issuer of a dossier is the entity that curates the collection of [[ref: evidence]] and attests to its composition by anchoring the container in the manner just described. That anchor makes a specific, verifiable assertion: at the time of issuance, the collection of evidence referenced within the dossier is the exact collection the issuer intended to present. The issuer does not necessarily attest to the veracity of the claims within the evidence, but rather to the integrity and composition of the collection itself.

### The Edges Attribute: Linking to Evidence

The primary payload of a dossier is not a set of direct claims, but rather a graph of references to external [[ref: evidence]]. This graph is contained within an [[ref: edges]] block (`e`), as defined in the ACDC specification [[2]]. This block MUST contain a JSON object where each key is a semantic label for an edge, and each value is an object describing the link to the external evidence.

A dossier MAY contain an unbounded number of edges, reflecting its core purpose of aggregating an arbitrary quantity and variety of evidence. The field names (keys) for these edges MAY be any valid JSON string, allowing issuers to provide semantically meaningful labels for the linked evidence (e.g.,
"vettingCredential", "forensicReport_01", "tnAllocationProof"), as demonstrated in the Verifiable Voice Protocol (VVP) specification.

#### The Dossier as Graph Root

An edge refers to its target by SAID, and an ACDC's SAID cannot be computed until its content is final. An ACDC can therefore point only at ACDCs that already existed when it was made, and edges can never form a cycle. A dossier and its evidence form a directed acyclic graph with the dossier at the top.

That structure does not by itself tell a verifier which ACDC is the dossier. A verifier that resolves a citation knows, because the citation names the dossier's SAID. A verifier that is handed a package (see *Presentation as a Self-Contained Package*) may not: nothing outside the package names the dossier, and the package may hold dozens of ACDCs. This specification fills that gap with a rule about what may be presented together.

Within any set of ACDCs presented together for evaluation, the dossier under evaluation MUST be the only ACDC that no other ACDC in the set points to. A verifier finds the dossier by finding that ACDC. If more than one ACDC in the set qualifies, the set is malformed, and the verifier can reject it before doing any cryptographic work.

The rule governs a single presentation, not dossiers in general. Other ACDCs often point at a dossier: a later version points at an earlier one through its `prev` edge or an annotation edge, and an unrelated dossier may cite it as evidence. Those ACDCs are legitimate. They cannot be presented alongside a dossier they point at, unless one of them is itself the subject. For example, if versions 1 and 2 of a dossier are presented together, version 2's `prev` edge points at version 1, so version 2 is the only ACDC nothing points to, and it is the dossier under evaluation.

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
                "$ref": "ENroDvI_lXRUa3p1UCxU6Pxp0DWDS1yZNexCq_1TQlcj"
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

This mandated flexibility has a direct consequence for implementers of verifier systems. A generic dossier verifier can be built to perform universal cryptographic validation—confirming anchors, SAIDs, and KEL consistency—for any dossier conforming to the base schema. However, such a generic verifier cannot be expected to understand the full semantics of every possible dossier. For instance, it can verify that an edge labeled "lunarPropertyDeed" is cryptographically linked, but it cannot know what that means or how to process it. Therefore, verification must be understood as a layered process. The first layer, cryptographic validation, is universal and defined by this specification. The second layer, semantic validation (e.g., "Does this dossier contain a valid TNAlloc credential for the phone number in question?"), is necessarily application-specific and requires context-dependent business logic. This separation allows the dossier format to be a universal building block for evidence aggregation across countless current and future use cases.

#### Recognizing a Dossier

The `allOf` and `$ref` construction above is how a schema *declares* that it is a dossier. Recognizing that declaration requires a validator that can resolve a `$ref` to a schema identified by SAID, which is a capability rather than a given.

Where a verifier can resolve such references, it SHOULD recognize a dossier by that means, because doing so requires no prior knowledge of the specific schema and therefore extends to dossier types the verifier has never encountered.

Where it cannot, a verifier MAY instead recognize a dossier by matching its schema SAID against the governed set in its acceptance policy. This is weaker: it recognizes only the dossier types the verifier was configured for, and it silently fails to recognize a conforming dossier of an unfamiliar type. That failure mode is acceptable because the correct outcome in that case is INDETERMINATE, which is precisely what an unrecognized schema SAID already produces. A verifier that recognizes dossiers this way MUST NOT treat the allowlist as a substitute for schema validation against the schema it does resolve, and SHOULD state which recognition method it implements, since the two differ in what they will accept from a stranger.

Implementers should be aware that `$ref` resolution is not currently available in the most widely deployed KERI implementation. In keripy at the time of writing, the schema validator used on both the issuance and verification paths is constructed without a resolver — `Schemer(raw=…)` in `src/keri/vdr/credentialing.py` and `src/keri/vdr/verifying.py` takes the default `JSONSchema()`, whose `resolver` is `None`, and `JSONSchema.verify` passes a reference registry to the validator only when a resolver is present. Schema integrity is additionally checked with `jsonschema.Draft7Validator.check_schema`. An unresolved `$ref` therefore fails, and a schema written against draft 2020-12 with an `allOf`/`$ref` to the base dossier SAID cannot currently be issued or verified by that stack. This is an implementation gap rather than a defect in the requirement, and the allowlist recognition described above is the interim mechanism available to deployments that meet it.

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

#### Edge Operators on Evidence Edges

An `{n, s}` pair with no operator field is sufficient for most dossier edges, and it is worth saying why, because an implementer who reaches for an explicit `o` on every edge is usually solving a problem that has already been solved by construction.

ACDC's default operators divide on whether the target has an issuee. A target without one — every [[ref: foreign-artifact-wrapper, Foreign Artifact wrapper]], every [[ref: observation-attestation, Observation Attestation]], and any other attestation about a thing rather than about a party — defaults to NI2I, which asks only whether the target was issued. A target that does have an issuee defaults to I2I, which additionally requires the referring ACDC's issuer to be that issuee.

For a dossier, I2I usually holds without anyone arranging it. A dossier's issuer is the party whose authority the dossier is exercised under, and the credential conferring that authority names that same party as its issuee, so the edge from dossier to role credential satisfies I2I as a matter of who the parties are. The same is generally true hop by hop up an authority chain, where each credential's issuer is the issuee of the one above it.

Issuers therefore SHOULD omit `o` on evidence edges and let the defaults apply, and SHOULD state it explicitly only where the intended semantics differ from the default. A verifier MUST apply the ACDC default when no operator is present rather than treating an absent operator as an absent constraint.

### Binding the Issuer's Authority

A dossier attests to the composition of a collection, and a verifier that has checked the anchor knows who made that attestation. It does not yet know whether that party was entitled to make it. For many dossiers the question does not arise: an artist collecting evidence of their own work needs no authorization. For any dossier issued on an organization's behalf, or under a license, role, or delegation, it is the first question a verifier asks.

A dossier SHOULD answer it structurally, with an edge to the credential that confers the authority under which the dossier was issued. The edge SHOULD be named `authority`. Reserving one conventional name lets a generic verifier locate the authority chain without knowing the dossier's domain, while every other edge name remains free-form and is resolved by SAID as before.

How deep the chain is spelled out in the dossier is a schema-level choice, and deployments reasonably differ. A dossier MAY carry sibling edges to several credentials that are jointly necessary — one vetting the organization, another conferring the signing role — or it MAY carry a single `authority` edge and leave the verifier to reach the rest by traversing edges that the referenced credential's own schema already makes normative. Both are conforming. The second is often preferable, since duplicating a hop the verifier must walk anyway creates two statements of one fact that can disagree.

The consequence for verifiers is that the absence of an edge proves nothing about the absence of a link. A verifier MUST follow an authority chain transitively to its root, through the referenced credentials' own edges, and MUST NOT require that every hop appear as a direct edge of the dossier. Where the chain does not terminate at a root named in the acceptance policy, the outcome is INVALID.

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
algorithms defined in the *Bytewise and Externalized SAIDs* specification [[8]],
and then issue a [[ref: foreign-artifact-wrapper, Foreign Artifact ACDC]] that attests to the [[ref: foreign-artifact, artifact]]'s identity
and provenance. The resulting wrapper is a standard ACDC and can be linked into
a dossier edge like any other [[ref: evidentum]].

Two algorithms are defined in [[8]] for saidifying opaque artifacts:

- The **bytewise SAID algorithm** (producing a **bSAID**) is appropriate for
  artifacts whose bytes can be rewritten after creation using native tooling —
  for example, a JPEG whose Exif metadata can be updated, or a Markdown file
  where a comment can be inserted. The artifact receives an insertion point
  containing the SAID, making the identifier intrinsic to the artifact's byte
  stream. A verifier can recover the SAID by scanning the raw bytes for the
  `SAID:` delimiter defined in [[8]].

- The **externalized SAID algorithm** (producing an **xSAID**) is appropriate
  for artifacts that cannot safely be rewritten after creation — for example,
  a compressed archive, an encrypted file, or a PDF whose cross-reference table
  would be invalidated by arbitrary byte modification. The SAID is carried in
  the filename under a constraint expressed inside the file content via the
  `XSAID:` delimiter defined in [[8]].

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
3. The `content_digest` SHOULD be a bSAID or xSAID as defined in [[8]].
4. Its `a` section MUST contain a `filename` field when `content_digest` holds
   an xSAID, and SHOULD contain one otherwise.

The `filename` requirement follows from how the externalized SAID algorithm
works. An xSAID is carried in the artifact's filename rather than in its bytes,
so the filename is an input to the identifier rather than incidental packaging.
A wrapper that omits it leaves a verifier unable to recompute what the wrapper
committed to. For bSAIDs and plain hashes the filename is not load-bearing, but
recording it is still worthwhile: it is what lets a verifier report *which*
artifact failed when a digest does not match, and artifacts routinely travel
alongside a dossier as a set of files rather than one at a time.

A reference schema and example for a Foreign Artifact ACDC are published
separately at [[9]]. Implementers MAY define specialized schemas that
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

### Curation: Assembling and Issuing the Dossier

Curation is the process of creating a dossier. This phase is typically performed in advance of any real-time transaction and involves the assembly and attestation of the evidence collection.

The normative steps for dossier curation are as follows:

1. Evidence acquisition: The entity intending to issue the dossier first acquires the necessary evidence from their respective authoritative sources. For example, a business might obtain a legal entity vetting credential from a qualified issuer, a telephone number allocation credential from its carrier, and a brand credential from a brand vetter.

2. Assembly: The issuer or [[ref: collector]] constructs the dossier ACDC data structure. This involves creating an edges block and populating it with named links that point to each acquired evidence artifact, as described in Section 3.

3. Iterative assembly and versioning: Some dossiers are static, but with others, as new evidence is collected or the status of investigation changes, the dossier evolves. To support this, [[ref: collector]]s MAY issue new versions of a dossier. A new version MUST be a valid ACDC that links to the previous version via a prev [[ref: edge]] or a schema-specific equivalent. This creates a verifiable chain of the dossier's history, allowing verifiers to traverse back through the lineage of the evidence collection.

4. Issuance initiation: For single-issuer dossiers, the [[ref: collector]] issues the fully assembled dossier ACDC by anchoring it. For joint issuance, the [[ref: collector]] provides the drafted ACDC to a [[ref: coordinator]]. The [[ref: coordinator]] then coordinates the endorsement and anchoring process among the designated members.

5. Anchoring: The [[ref: collector]] or [[ref: finalizer]] saidifies the dossier, places a seal containing that SAID in an event, and anchors the event in the key event log (KEL) of a KERI AID they control — directly, or by way of a transaction event log whose events that KEL anchors. The private keys authoritative for that AID sign the anchoring key event, not the dossier itself. This act creates a permanent, non-repudiable attestation to the dossier's content. In joint issuance, the anchor may be distributed across several KELs or consolidated in a finalization event.

6. Publication: The issuer or [[ref: coordinator]] publishes the issued dossier ACDC at a stable, publicly resolvable location, typically one or more HTTP URLs. This allows authorized verifiers to fetch the dossier when it is cited.

### State Management and Metadata Overlays

For dossiers used in procedural contexts (e.g., legal proceedings, insurance adjustments), the mere existence of evidence is insufficient; its status relative to the procedure matters. An artifact may be "marked for identification," "admitted," "objected to," or "stricken." Because ACDCs are immutable, an issuer cannot simply modify the metadata of an existing [[ref: edge]].

To manage these state transitions, dossiers MUST use **[[ref: annotation-edge, Annotation Edges]]**. An annotation edge is an edge in a new version of the dossier that points to an artifact (or an edge) in a previous version. The payload of the annotation edge carries the new state or ruling. For example, a "Court Case Dossier v2" might contain an edge labeled `ruling_101` that points to the SAID of `exhibit_A` (from v1) with the attribute `status: "admitted"`. Verifiers MUST process the dossier by traversing the graph to resolve the "effective state" of each piece of evidence, applying the latest annotations found in the chain.

### Temporal Pinning

Many dossiers require evidence of dynamic states, such as a bank balance, a credit score, or a current employment status. Direct links to live APIs are unverifiable in a static context. To include dynamic data, issuers MUST use **Temporal Pinning**.

This process requires the [[ref: assembler]] (or a trusted "[[ref: oracle]]" service) to:
1. Observe the dynamic state at a specific instant (`Time T`).
2. Wrap that observation in an [[ref: observation-attestation, Observation Attestation]] ACDC.
3. Anchor that ACDC in a KEL.

The dossier then links to this static, timestamped Observation Attestation. This effectively "freezes" the data stream at a specific block height, allowing the dossier to assert, "The borrower had $50,000 in this account at the exact moment this dossier was assembled," rather than "The borrower has $50,000 now."

### Citation: Referencing the Dossier in Protocols

Because dossiers are designed to be stable, long-lived, and potentially large data structures, they are generally not transmitted in their entirety within real-time communication protocols. Instead, they are cited.

A [[ref: citation]] is a reference that allows a verifier to locate and retrieve the full dossier. The normative requirement for a dossier citation is that it MUST be a resolvable identifier that enables a verifier to fetch the complete and unmodified dossier ACDC. The canonical implementation of this is the Out-of-Band Invitation (OOBI) URL used in the evd (evidence) claim of a VVP passport. An OOBI is a specialized URL that points to a resource serving the ACDC and its associated KERI proofs.

### Presentation as a Self-Contained Package

Citation assumes the verifier goes and gets the dossier. Some dossiers are instead delivered, complete, to a party who is expecting them: a filing submitted to a regulator on a deadline, a disclosure produced to opposing counsel, an evidence package handed to an auditor. In these cases there is no advantage in publishing an OOBI for a recipient who is known in advance, and often a positive requirement not to publish anything at all.

A dossier MAY therefore be presented as a self-contained package: a single transferable unit carrying the dossier, every ACDC reachable from it, the key event logs and transaction event logs needed to establish the key state and revocation status of every issuer in that graph, and any opaque artifacts whose wrappers the dossier references. CESR provides a natural serialization for such a package, and IPEX provides a natural exchange protocol, but this specification does not mandate either.

The defining property is self-containment. A conforming package MUST be verifiable from its own contents alone, with no network access at the time of verification. A verifier SHOULD ingest a package into a fresh, empty datastore and evaluate it there, so that nothing it happens to already know is silently supplying a fact the package failed to carry. A package that verifies only against a populated datastore has not demonstrated what it appears to demonstrate, and the failure will surface later, when an auditor tries to replay it somewhere else.

Two further consequences follow:

- No citation names the dossier, so a verifier identifies it by the rule under *The Dossier as Graph Root*: it is the only ACDC in the package that no other ACDC points to.
- The act of delivery SHOULD itself be authenticated, separately from the dossier's own anchor. A dossier's anchor establishes who assembled the collection and when; it says nothing about who transmitted it, to whom, or under what obligation. Where submission has consequences of its own — a filing deadline, a certification made to a regulator — the submitter SHOULD sign or anchor the transmission, so that the act of submitting is as non-repudiable as the content submitted.

Self-containment is also what makes a package durable evidence rather than a delivery mechanism. The same bytes can be replayed years later, against the same algorithm and the same referenceTime, by someone who was not party to the original exchange and cannot reach anyone who was.

### Verification: Algorithm for Validation

#### Verification Outcomes

Verification of a dossier yields one of three outcomes. Two of them are the familiar ones; the third exists because of the layered verification described under *Base JSON-Schema Definition*, where cryptographic validation is universal but semantic validation is not.

- **VALID.** Every check in the algorithm below passed, and every credential reachable from the dossier carries a schema the verifier governs. The verifier can act on the dossier.
- **INVALID.** A check failed definitively: a SAID that does not recompute, an anchor that is absent or made under keys that were not authoritative, a chain that does not reach a trusted root, a credential revoked as of the referenceTime, an artifact whose bytes do not match its committed digest, a package that breaks the rule under *The Dossier as Graph Root*. The verifier MUST NOT act on the dossier.
- **INDETERMINATE.** The structure and the cryptography are sound, but the verifier encountered something it is not competent to judge — most commonly a credential in the graph whose schema is outside the set the verifier governs. Nothing is known to be wrong. The verifier simply cannot say the dossier is good, and MUST NOT treat it as though it could.

The third outcome matters more than it may appear. A dossier is designed to aggregate evidence from domains its verifier may not know, so meeting an unrecognized schema is an ordinary event rather than an error. A verifier with only two outcomes must either reject those dossiers, which makes the extensibility the model depends on unusable, or accept them, which silently confers trust on credentials nobody evaluated. Naming the third case lets a verifier report exactly what it could not decide, and lets a governing framework decide whether that is tolerable in its context.

A verifier MUST return INVALID rather than INDETERMINATE whenever a check fails definitively, even if an unrecognized schema is also present: an established failure is not made uncertain by the presence of an unknown. Conversely, a verifier MUST NOT return VALID for a dossier containing any node it could not evaluate.

#### Verifier Acceptance Policy

INDETERMINATE is only decidable if "what the verifier governs" is a stated set rather than an implicit one. A conforming verifier therefore operates under an explicit acceptance policy, configured in advance and independent of any particular dossier. The policy MUST state at least:

- **Governed schema SAIDs.** The set of schemas the verifier is competent to evaluate. A credential reachable from the dossier whose `s` falls outside this set yields INDETERMINATE.
- **Trusted root AIDs.** The identifiers at which an authority chain must terminate. A chain that terminates anywhere else yields INVALID; it is not an unknown, it is a chain to the wrong root.
- **Reference time.** The instant as of which revocation and validity are evaluated, as described under [[ref: reference-time, referenceTime]].

Stating the policy explicitly, rather than letting it emerge from whatever schemas an implementation happens to have cached, is what makes two verifiers' verdicts comparable, and what lets a verifier explain a refusal in terms a submitter can act on.

#### The Algorithm

The verification process for a dossier requires a citation and a [[ref: reference-time, referenceTime]] as inputs, together with the acceptance policy above. To support joint issuance, the algorithm follows these steps:

1. Fetch dossier: resolve the citation to retrieve the dossier ACDC.

2. Validate dossier integrity: calculate the SAID of the retrieved data and ensure it matches the expected SAID from the citation.

3. Check the graph root: where the dossier was presented as part of a package rather than fetched by citation, confirm that it is the only ACDC presented that no other presented ACDC points to, as required under *The Dossier as Graph Root*. A package in which more than one ACDC meets that test is INVALID.

4. Check governance: confirm that the dossier's own schema appears in the governed set named by the acceptance policy, and apply the same test to every credential reached during traversal in step 7. A schema outside the governed set yields INDETERMINATE.

5. Determine issuance model: inspect the attributes block for an `fi` [[ref: finalization-identifier, finalization identifier]] and the edges block for a joint-issuance [[ref: threshold-operator, threshold operator]] (`MxN`, `RMxN`, `MxQ`, or `RMxQ`) in an edge group's `o` field.

6. Validate anchors:
   a. If `fi` is present and non-null, locate the finalization event in the KEL of the AID it names. Verify that the event carries the threshold-satisfying endorsements for the relevant operator.
   b. If `fi` is absent or null but a threshold operator is present, evaluate each slot in the operator's edge group. A slot is **Endorsed** only when it references an Endorsement ACDC with `disp` `"endorse"` and `act` appropriate to the operation, issued by the expected endorser and anchored in that endorser's KEL. Confirm that the weights (`w`) of the Endorsed slots sum to at least unity (1) — for the qualified operators, using the uniform member weight the operator declares. For the qualified operators, additionally verify that each counted endorsement carries a qualification proof (`e.qp`) that validates against the schema named in the operator's `qs` field.
   c. For standard dossiers with a single issuer, retrieve the issuer's KEL and locate the event anchoring a seal that contains the dossier's SAID — either directly, or by way of a transaction event log whose events the KEL anchors. Verify that anchoring event's signatures against the key state the KEL establishes as authoritative *at that event's position in the log*, not against the key state current at the referenceTime; an anchor remains verifiable across any number of later rotations, and requiring the referenceTime key state would defeat that property. Then confirm that the anchoring event precedes the referenceTime.
   d. Only if the dossier was authenticated by an attached signature under *Ephemeral Dossiers With Attached Signatures*, verify that signature against the issuer's current key state. A verifier MUST reject such a dossier when the referenceTime is not the present, and SHOULD reject it when the dossier was retrieved from a cache or a published location rather than received directly within the transaction it authenticates.

7. Recursive graph traversal: for each named edge in the edges block, fetch the referenced artifact and perform this validation algorithm recursively. Where an `authority` edge is present, follow it transitively through the referenced credentials' own edges, as described under *Binding the Issuer's Authority*, and confirm that the chain terminates at a root named in the acceptance policy.

8. Check revocation status: for the dossier and every node in the evidence graph, consult the relevant KELs or status registries for revocation events effective at the referenceTime.

9. Check artifact digests: for every node in the graph that is a [[ref: foreign-artifact-wrapper, Foreign Artifact wrapper]] whose artifact accompanies the dossier or is otherwise available to the verifier, recompute the artifact's digest using the algorithm identified by the CESR primitive code of the wrapper's `content_digest`, and compare. A mismatch MUST fail verification, and the verifier SHOULD report which artifact failed. Where the artifact is not available, the wrapper itself may still verify, but the artifact does not: a verifier MUST NOT treat a valid wrapper as evidence that the bytes it describes are intact, and SHOULD report the artifact as unchecked rather than as passing.

10. Apply semantic rules: apply application-specific policy rules once cryptographic validation is complete.

The steps are ordered, and a verifier SHOULD short-circuit on the first that does not pass, since later steps are rarely meaningful once an earlier one has failed. A verifier SHOULD also retain the per-step result, not merely the final outcome. Where a dossier is used for compliance, discovery, or audit, the question asked later is usually not whether verification succeeded but which checks were performed and against what state, and a step-by-step record answers that without requiring the original verifier to be available.

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
  differ if the dossier was finalized and anchored at a later time.

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

- **`attest`**: A declaration the issuer makes in their own voice about the collection, as part of the act of issuing it. An object with a `statement` field holding human-readable text, and a `confirmed` boolean recording whether the issuer affirms that statement. Example: `{"statement": "I certify that the materials enumerated here are complete and accurate to the best of my knowledge.", "confirmed": true}`. The boolean is not redundant with the issuer's anchor. An anchor establishes that the issuer issued this dossier; `confirmed` establishes whether the issuer adopted the declaration it contains, so a dossier can carry a required declaration and record that it was withheld. Where the declaration has legal effect, the exact wording usually comes from the governing framework, and `gov` or `gov_rules` SHOULD identify that framework.

- **`manifest`**: An enumeration of the components the dossier is expected to contain, keyed by an identifier drawn from the governing framework. Each entry is an object carrying at minimum a `status`, and optionally a human-readable `name`, a `reason`, a `due` date, and an `edge` field naming the edge that carries that component's evidence. The following statuses are defined; implementers MAY define others, and SHOULD reference the vocabulary their framework uses:

    * `provided` — the component is present, and `edge` names the edge that carries it.
    * `pending` — the component is required and will follow, with `due` giving the date it is expected by.
    * `not_applicable` — the component is not required of this issuer in this instance, with `reason` explaining why.
    * `withheld` — the component is required, is not supplied, and is not promised, with `reason` recording the grounds.

#### Attesting to Completeness

The [[ref: manifest]] field exists because some dossiers must attest to their own negative space. In most of the patterns this specification describes, a dossier asserts what its issuer gathered, and a verifier's question is whether each item is authentic. In regulated filing, accreditation, audit and discovery, the harder question is the opposite one: is anything missing, and was the omission disclosed? The consequential failure is rarely a forged document. It is an item that was required, was not supplied, and was never mentioned.

A dossier without a manifest cannot distinguish the three cases a supervising authority most needs to tell apart: a component that is absent because it does not apply, one that is absent because it is still coming, and one that is absent because the issuer chose not to supply it. Enumerating every expected component, including the ones with no corresponding edge, makes each of those an explicit, attributable claim rather than an inference from silence — and because the enumeration is inside the dossier, the issuer's anchor commits to it exactly as it commits to the evidence graph. An issuer who omits a required item and marks it `not_applicable` has made a false statement that survives in a duplicity-evident log, which is a materially different position from having simply left it out.

A manifest entry that names an edge does not violate the rule that the `a` section MUST NOT carry evidenta. The entry carries no evidence; it carries the issuer's account of what the collection was supposed to contain, and a pointer to where the corresponding evidence sits in `e`. The evidence itself remains reachable only through edges, and a verifier that ignores the manifest entirely still recovers the full evidence graph. What it loses is the issuer's claim about completeness, which is metadata about the collection rather than a member of it.

Verifiers SHOULD treat manifest processing as semantic validation rather than cryptographic validation. Whether a `withheld` component is acceptable, or a `pending` one is overdue, is a policy question belonging to the governing framework. What this specification requires is that where a manifest entry has `status` `provided`, its `edge` field MUST name an edge that is present in the dossier's `e` section, so that the two accounts of the collection cannot silently disagree.

## Joint Issuance
A dossier may be assembled and issued by a single party. For example, an artist who wishes to collect cryptographic evidence of their creations may do so as a solo activity. However, many dossiers snapshot evidence contributions from multiple parties, and so represent a group work product that needs an aggregate approval mechanism. In such cases, authorizing the issuance of the ACDC that references all the individual pieces of evidence is managed with joint issuance.

### Logic
Joint issuance is best understood not as a single, uniform approach to approval, but as a family or style of approval strategies. It maps onto the problem domain of coordinated control in multi-agent systems, which has been formally studied in robotics, AI, military science, and similar fields. Three variants of cooperative control are regularly mentioned in the literature [[5]] [[6]] [[7]]:

* leader-follower 
* behavior-based control
* virtual structures

A dossier can be approved using any of these variants, and this specification normatively describes success using primitives relevant to all three. The description below focuses on the leader-follower approach because it is the simplest to understand and lends itself most easily to deterministic guarantees. Whatever cooperative control mechanism is chosen, the process involves asynchronous endorsement that converges on a common goal, possibly over a significant span of time. Unlike group multisig, which requires synchronous agreement on key event log (KEL) sequence numbers, joint issuance relies on logic within the ACDC layer. This lets members anchor their endorsements of a dossier at different times and via different channels, each in their own KEL, without immediate impact on a shared one.

The validity of a jointly issued dossier is determined by satisfying a [[ref: threshold-operator, threshold operator]] within its [[ref: edge]] graph. Because the logic is decoupled from key management, issuance and verification have more flexibility.

### Leader-Follower Roles
When joint issuance is coordinated with a leader-follower strategy, three distinct roles emerge, that may be performed by the same or different entities:

* Collector: the entity that assembles the evidence artifacts and defines the initial dossier structure.
* Coordinator: the entity that, once collection is finished, initiates the issuance action and distributes the candidate dossier for endorsement.
* Finalizer: any entity that, upon observing that an issuance threshold is met, submits a finalization event to a KEL.

### Threshold Mechanics
A joint issuance is satisfied by a weighted [[ref: threshold-operator, threshold operator]] placed in the operator field (`o`) of an edge group within the dossier's edges block, following ACDC operator conventions. The operator's member edges are *slots*. Each slot carries a weight in its reserved `w` field, and the group is satisfied when the weights of the slots that hold valid endorsements sum to at least **unity** (1). This is the same fractionally weighted threshold KERI uses for key-event signing thresholds (`kt`): the threshold itself is the fixed constant 1, so there is no separate count field — how many endorsements are enough, and how much each is worth, lives entirely in the weights.

For an ordinary *m*-of-*n* rule among equal endorsers, each of the *n* slots is given weight `1/m`, so that any *m* of them sum to unity while any *m*−1 fall short. Unequal weights express weighted governance (a senior endorser whose approval counts double carries `2/m`), and grouped weights express nested AND/OR-of-threshold rules, exactly as KERI's nested `kt` lists do. A schema MAY fix the operator, the weights, and the set of candidate endorsers, or MAY defer some or all of these to the dossier instance, so the rules are actualized only when the issuance is proposed.

#### Slot dispositions
Within a threshold operator's edge group, each member edge is a slot that points (via its `n` field) to an endorsement ACDC, names the schema that endorsement MUST satisfy (via its `s` field), and assigns the endorsement a weight (via its reserved `w` field). The expected endorser is identified by the issuer (`i`) of the ACDC the slot references. A slot is in exactly one of three dispositions:

* **Pending**: the slot references a placeholder meta ACDC that names the candidate endorser but that the candidate has not anchored (or the slot is null). This is the initial state the dossier creator establishes for each candidate. A pending slot contributes nothing to the threshold sum; it records only that an endorsement is anticipated from the named candidate.
* **Endorsed**: the slot references an [[ref: endorsement]] ACDC issued by the candidate and anchored in the candidate's KEL, with a `disp` (disposition) of `"endorse"` and a `said` attribute equal to the dossier's SAID. This is an authenticated act, and the slot's weight `w` is added to the threshold sum.
* **Declined**: the slot references the same [[ref: endorsement]] ACDC, issued by the candidate and anchored in the candidate's KEL, but with a `disp` of `"decline"` — a [[ref: declination]]. This is an authenticated refusal. Its weight is not added to the threshold sum, but, unlike a pending slot, it records attributable dissent — distinguishing a candidate who was asked and refused from one who has not yet acted.

Because only the candidate's anchor authenticates the candidate's decision, a pending slot and an absent slot are equivalent in trust terms: neither attributes any act to the candidate. An active "no" MUST therefore be expressed as an anchored [[ref: declination]], never as a null or unanchored slot.

### Threshold Operators
The following operators are defined for the `o` field of an edge group to support joint issuance. Each is satisfied when the weights (`w`) of its **Endorsed** slots sum to at least unity (1).

All four operators use a single [[ref: endorsement]] schema (SAID `ECRjgun8t3cay_YBiVxEY-qXKCz37oUrvE5GvmySwxCh`); a slot's `s` field names this one schema throughout. Three fields on the endorsement distinguish the cases: `disp` (`"endorse"` to add the slot's weight, `"decline"` to record dissent), `act` (`"issue"` or `"revoke"`), and the optional qualification-proof edge `e.qp` (present for the qualified operators, omitted otherwise). The operator's own name, together with the `act` of the endorsements it counts, distinguishes issuance from revocation.

* `MxN` ("M of N"): an issuance [[ref: threshold-operator, threshold operator]]. The edge group contains exactly *N* slots, one per candidate endorser, each carrying a weight `w`, and is satisfied when the weights of the **Endorsed** slots sum to at least unity. For the common equal-weight case, each slot is given `w` of `1/m`, so that any *m* of the *n* endorse to reach unity. Each counted endorsement MUST carry `act` `"issue"` and `disp` `"endorse"`, and omits the `e.qp` proof edge. Because the *N* candidates are enumerated structurally as slots — each naming its expected endorser through the issuer of the ACDC it references — the operator embodies an *m of n* pattern without any separate enumeration of potential endorsers. An example is a judicial decision jointly issued by *m* of *n* named justices.
* `RMxN` ("Revocation M of N"): a [[ref: revocation-operator, revocation operator]] with the same mechanics as `MxN`, applied to revocation. Its slots likewise carry weights summed to unity, and each counted endorsement MUST carry `act` `"revoke"`. The set of revocation slots MAY be identical to, overlap, or be disjoint from the issuance slots, and the revocation weights MAY differ from the issuance weights, so the authority to revoke can be configured independently of the authority to issue.
* `MxQ` ("M of Qualified"): an issuance threshold operator for an open-ended set of qualified endorsers. Unlike `MxN`, the slot count is not fixed in advance; slots are added as qualified endorsers act. Because the members are not known when the dossier is assembled, the operator declares a uniform member weight in its own `w` field, applied to each qualified **Endorsed** endorsement; the group is satisfied when those weights sum to unity (equivalently, when at least `1/w` qualified endorsers have endorsed). Each counted endorsement MUST carry `act` `"issue"`, `disp` `"endorse"`, and a qualification-proof edge `e.qp`. The edge group MUST also carry a `qs` field naming the SAID of the schema that each endorser's qualification proof MUST satisfy; the dossier creator chooses this proof schema to suit the use case, since the proof of qualification differs from one context to another. This models an endorsement open to anyone who can prove they are qualified — for example, "any licensed physician in good standing."
* `RMxQ` ("Revocation M of Qualified"): a revocation threshold operator with the same mechanics as `MxQ`, applied to revocation. It likewise declares a uniform member weight in its `w` field summed to unity, and each counted endorsement MUST carry `act` `"revoke"` and a qualification-proof edge `e.qp`. As with `RMxN`, the qualified revoker set and weights MAY be configured independently of issuance.

A **Declined** disposition under any of these operators is the same endorsement ACDC, anchored with `disp` `"decline"` and the matching `act`. For the qualified operators, whether a declination must also carry a qualification proof is a policy choice left to the governing schema; a declination never adds its weight to the threshold sum in any case.

### Finalization
A joint issuance MAY advertise a finalization event to assist verifiers that do not perform recursive graph traversal. This is signaled by the `fi` ("finalization identifier") field in the dossier's attributes (`a`) section, rather than by an edge operator.

* When `fi` is present and non-null, it holds the AID whose KEL is expected to carry a finalization event for this joint issuance. A [[ref: finalizer]] that observes the threshold to be met anchors the threshold-satisfying proofs in that AID's KEL — typically a group AID — so that the aggregate evidence is collected in one predictable place. A verifier SHOULD use this finalization event as the definitive proof of issuance.
* When `fi` is absent or null, no finalization event is promised. A verifier MUST instead gather the endorsements from the participants' individual KELs and confirm directly that the threshold is met.

### Revocation
Revocation logic in a joint issuance is defined independently of issuance logic, using the `RMxN` or `RMxQ` operator.

* Default: if no revocation operator is present, the threshold required to revoke a dossier is identical to the threshold required to issue it.
* Asymmetric thresholds: a dossier MAY specify different operators, slot sets, or weights for issuance and revocation. For example, a dossier may require a majority for issuance (equal weights) but let a single administrative AID revoke (that slot weighted at unity on its own).

## Dossiers and Derivative References

A dossier is intentionally heavy. It may be assembled once and issued jointly by many parties, may carry a graph of arbitrarily many evidence items, and may require a verifier to fetch and validate every node in that graph against multiple KELs. This cost is acceptable because a dossier is designed for reuse: curation happens once, and the resulting artifact serves as an authoritative reference for many later transactions, verifiers, and decisions.

In transactional protocols, however, the dossier itself is rarely transmitted. Sending a multi-kilobyte ACDC and requiring full recursive verification on every call is impractical for real-time use cases such as a phone call, a checkout step, or an API request. Instead, the transactional payload carries a lightweight [[ref: derivative]] that references the dossier. The dossier remains the primary, persistent artifact; the derivative is short-lived, single-purpose, and cheap to produce and validate.

This specification recognizes two derivative forms:

- **Citation.** A resolvable identifier (canonically an OOBI URL) that lets a verifier fetch the full dossier and run the verification algorithm. Citations are defined under *Citation: Referencing the Dossier in Protocols* above.

- **Token.** A short-lived signed object that carries enough context for an immediate verification decision and embeds the dossier SAID as an evidence pointer. A token is one of the few artifacts in this specification that genuinely bears an attached signature, in the sense defined under *How a Dossier Is Issued: Anchoring, Not Attached Signatures*; it can afford one because its lifetime is measured in seconds and it is never expected to outlive a key rotation. A minimal token might take this shape:

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

A derivative MUST cryptographically bind to the dossier it references — minimally by including the dossier SAID under whichever mechanism authenticates the derivative: the signature over a token's payload, or the resolvable identifier that constitutes a citation. A derivative MUST NOT be treated as independent evidence: its authority derives entirely from the dossier, and its trust value collapses to that of the dossier alone if the binding cannot be checked.

Derivatives inherit the dossier's revocation lifecycle. When a verifier evaluates a derivative, it MUST consult the dossier's revocation state effective at the verification time, not at the time the derivative was issued. A token issued before its referenced dossier was revoked is not valid after the revocation event, even if the token's own `exp` has not yet passed.

This split between dossier and derivative separates two questions that are conflated in conventional bearer credentials:

- *What was attested, and by whom?* This lives in the dossier and is curated once, then amortized across many transactions.
- *Who is presenting it now, in what session, under what immediate constraints?* This lives in the derivative and is bound to the specific transaction through ephemeral fields (`iat`, `exp`, `aud`, `nonce`).

Implementers MAY define additional derivative forms — for example, a summary that exposes a redacted subset of the dossier's proximate metadata for human review, or a blinded proof that attests dossier validity without revealing its SAID (see *Mitigation Strategies for Unwanted Correlation* below). Any such form is subject to the binding and revocation requirements above. Replay protections for transactional citation messages are addressed under *Replay Attack Mitigation in Citation Protocols* below.

## Security Considerations

### Integrity and Non-Repudiation via KERI

The security of the dossier model is founded on the cryptographic primitives provided by KERI and ACDC.

Integrity: Self-addressing identifiers (SAIDs) guarantee the integrity of the dossier and all ACDC-native evidence within its graph. A SAID is a cryptographic hash of an object's canonical content. Any modification to the data results in a different SAID, making tampering immediately evident.

Non-repudiation: Anchoring makes the act of issuing a dossier non-repudiable. The issuer commits the dossier's SAID into a key event log (KEL) — a permanent, publicly auditable, and tamper-evident log of all significant actions — by placing a seal in a key event that the issuer's authoritative keys sign. The signature is on that key event rather than on the dossier; what a verifier relies on is the presence of the commitment in a log the issuer cannot rewrite and witnesses can attest to. In joint issuance, the collective anchors of all participating members in their respective KELs provide non-repudiation. A finalization event, if used, provides a single cryptographic record of this consensus.

### Replay Attack Mitigation in Citation Protocols

The dossier itself is a stable, long-lived artifact designed for reuse. As such, the primary risk of replay attacks exists at the level of the protocol that cites it. An attacker could capture a valid citation message and re-submit it in a different context.

To mitigate this, any protocol that cites a dossier MUST incorporate ephemeral, context-specific data into the payload that is cryptographically signed. This data MUST bind the citation to a unique transaction using timestamps to create a narrow window of validity, originator and destination identifiers, and unique nonces to prevent identical replays.

### Verifier Trust and Root of Trust Management

The dossier model operates on a decentralized root of trust. A verifier does not rely on a single authority but makes explicit trust decisions about a plurality of evidence issuers. In joint issuance, this trust is distributed across the member AIDs defined in the threshold.

The foundation of this trust is the KERI witness infrastructure. Witnesses are independent services that act as notaries for an AID's KEL. By requiring an issuer to report its key events to a set of witnesses, the system gains high availability and duplicity detection. Verifiers SHOULD consult multiple witnesses to ensure they have a consistent and complete view of an issuer's KEL, thereby protecting against duplicity and compromise.

One configuration deserves separate mention, because it is common in regulated settings and because it simplifies the trust decision considerably. Where a dossier is submitted to the same authority that roots the issuer's credential chain — a regulator receiving a filing from an entity it licensed, an accreditor receiving a renewal from a body it accredited — the verifier and the root of trust are the same party. The verifier is then not weighing whether to extend trust to someone else's root. It is confirming that the chain terminates at itself, and rejecting anything that does not.

This closed loop removes most of the judgment from trust configuration, but it does not remove the configuration. The authority must still state which root AIDs it recognizes as its own and which schemas it governs, because a chain that reaches the right root through a credential type the authority never defined is not something the authority can evaluate. It also does not remove the need for witnesses: an authority verifying a submission against its own root still depends on witnessed KELs to detect duplicity in the submitter's key history, and SHOULD apply the same multi-witness discipline it would apply to a stranger.

### Long-Term Auditability and Historical Analysis

The KERI-based dossier ecosystem supports long-lived auditing. Because KELs provide a complete, verifiable, and sequenced history of an identifier's key state, a verifier can perform validation for any arbitrary point in the past. 

This capability is critical for use cases involving compliance and legal discovery. An auditor can determine if a dossier and its entire evidence graph were valid at the time of a transaction, based on the key states and revocation information known at that moment. This provides non-repudiable historical accountability.

## Privacy Considerations

### Graduated Disclosure Mechanism

Dossiers MAY support privacy-preserving disclosure of their contents through the graduated disclosure mechanism inherent to the ACDC specification. An ACDC is a hierarchical JSON object, and its SAID is computed recursively: the hash of a parent object is derived from its scalar values and the SAIDs of its child objects.

This structure means that any child object within an ACDC can be replaced by its SAID without altering the SAID of the parent object. Because what the issuer anchored is that top-level SAID, redaction leaves the issuer's commitment intact: the redacted form still hashes to the SAID sealed in the issuer's KEL. This is a further consequence of anchoring rather than signing — had the issuer signed the container's bytes, any redaction would have invalidated that signature. This allows the holder or issuer of a dossier to generate redacted versions of the ACDC. These versions selectively hide sensitive information while remaining cryptographically verifiable. In joint issuance, redaction does not affect the validity of member seals anchored in KELs, as those seals point to the immutable SAID of the root dossier.

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
* **Mechanism:** This pattern employs the **[[ref: oracle, Oracle]]** or **[[ref: oracle, Observer]]** role. The assembler (or a trusted third-party service) queries the dynamic data source at `Time T`. This observation is then wrapped in an Observation Attestation ACDC, which the observer anchors in its own KEL, that effectively says, "I observed Account X having Balance Y at Block Height Z." The dossier links to this static attestation. This converts a stream of data into a verifiable snapshot, allowing a loan officer to verify "Funds Available" at the exact moment of the application.

### Clinical Trials: The Predicate Dossier

This profile introduces the **Predicate Dossier** pattern, essential for environments with strict privacy regulations (e.g., HIPAA, GDPR) where raw data cannot be shared.

* **Goal:** Prove eligibility or compliance without disclosing the underlying sensitive data.
* **Key Concept: Zero-Knowledge Predicates.**
* **Mechanism:** Instead of linking to a raw evidence file (e.g., `blood_test_results.pdf`), the dossier links to a **[[ref: predicate-edge, Predicate Edge]]**. This edge points to a Zero-Knowledge Proof (ZKP) or a derived cryptographic claim generated from the raw data.
    * *Example:* The dossier asserts `inclusion_criteria_met: true`. The evidence is a ZKP proving that "Subject Age > 18 AND HIV_Status == Positive" without revealing the subject's birthdate or specific medical markers.
* **Verification:** The verifier validates the cryptographic proof rather than parsing the document, enabling high-assurance compliance without data leakage.

### The Petition: The Open-Endorsement Dossier

This profile demonstrates the **Open-Endorsement Dossier** pattern, designed for cases where the set of participants is large or cannot be fully enumerated at the start of the curation process.

- **Goal:** Collect a threshold of endorsements from a distributed and potentially dynamic set of endorsers.
- **Key Concept: Asynchronous Threshold Satisfaction.** Unlike a standard multisig group that requires tight coordination among a fixed set of peers, this pattern allows any AID that satisfies the criteria defined in the dossier schema to contribute an endorsement.
- **Mechanism:** The coordinator initiates the dossier and distributes the candidate ACDC. Because the qualified endorser set is open-ended, the dossier uses the `MxQ` operator to define the conditions for validity: enough qualified, unique endorsements that their weights sum to unity (with a uniform per-member weight `w`, that means at least `1/w` endorsers), where each endorser proves qualification through the proof schema named in the operator's `qs` field. Participants signify their agreement by issuing a qualified Endorsement ACDC and anchoring it in their individual KELs.
- **Verification:** A verifier confirms the dossier is valid by observing that enough qualified endorsers' KELs carry a valid endorsement of the dossier SAID for their weights to reach unity. The coordinator may set the dossier's `fi` field and finalize the issuance once that point is reached, simplifying this check for third parties.

### Regulatory Filing: The Attested Submission Dossier

This profile illustrates the **Attested Submission Dossier** pattern, which covers a recurring obligation to file a defined set of materials with a supervising authority: an annual accreditation renewal, a licensing return, an audit package, a grant report, a customs declaration. These filings are alike in shape. A checklist fixed by the authority says what must be supplied; a named individual assembles it and certifies it on the organization's behalf; and the authority that receives it is the same body that authorized the filer to act.

- **Goal:** Discharge a filing obligation with one self-contained object that establishes what was supplied, what was not, who certified it, and under what authority — and that remains verifiable years later, during an audit of the filing itself.
- **Key Concept: Attested Completeness.** The distinguishing feature is not the evidence but the enumeration. Other patterns attest to what the issuer gathered; this one attests to what the framework required. The dossier's `manifest` lists every expected component, including the ones with no edge behind them, each marked `provided`, `pending`, `not_applicable` or `withheld` with a reason, and the `attest` field carries the certification the framework puts in the filer's mouth. Omission becomes an attributable claim instead of an inference from silence.
- **Mechanism:** Each supplied document is wrapped in a [[ref: foreign-artifact-wrapper, Foreign Artifact wrapper]] committing its digest — typically an xSAID, since filings are dominated by PDFs whose bytes cannot be rewritten without breaking them. The wrappers become edges named for their checklist line items, and an `authority` edge binds the filer's role credential, which chains through the organization's identity credential to the authority's own root (see *Binding the Issuer's Authority*). The filing is delivered as a self-contained package rather than published for later retrieval, because it is pushed on a deadline to a recipient known in advance, and the submitter authenticates the act of submission separately from the dossier's own anchor.
- **Verification:** The authority is simultaneously the root of trust and the relying party (see *Verifier Trust and Root of Trust Management*), so it accepts only chains terminating at its own root and credentials minted under schemas it governs. Its acceptance policy names its own root and the schemas it governs, which in this configuration it can populate authoritatively rather than by judgment, so a credential minted under a schema it never defined is correctly INDETERMINATE rather than refused. Beyond the standard algorithm, it reconciles the manifest against the edges, re-hashes every accompanying document against its wrapper's committed digest, and applies its own policy to the entries the filer marked absent. Because the package is self-contained, the same check can be replayed against the same bytes at any later date, which is what makes the filing auditable rather than merely received.

## Bibliography

[[spec]]

[1]. KERI
[1]: https://trustoverip.github.io/kswg-keri-specification/

[2]. ACDC
[2]: https://trustoverip.github.io/kswg-acdc-specification/

[3]. CESR
[3]: https://trustoverip.github.io/kswg-cesr-specification/

[4]. Verifiable Voice Protocol
[4]: https://www.ietf.org/archive/id/draft-hardman-verifiable-voice-protocol-05.html

[5]. Beard, Lawton, and Hadaegh
[5]: Beard, R. W., Lawton, J., and Hadaegh, F. Y. 2001. A coordination architecture for spacecraft formation control. IEEE Transactions on Control Systems Technology 9, 6 (November 2001), 777–790. https://doi.org/10.1109/87.960341

[6]. Oh, Park, and Ahn
[6]: Oh, K.-K., Park, M.-C., and Ahn, H.-S. 2015. A survey of multi-agent formation control. Automatica 53 (March 2015), 424–440. https://doi.org/10.1016/j.automatica.2014.10.022

[7]. Fax and Murray
[7]: Fax, J. A., and Murray, R. M. 2004. Information flow and cooperative control of vehicle formations. IEEE Transactions on Automatic Control 49, 9 (September 2004), 1465–1476. https://doi.org/10.1109/TAC.2004.834433

[8]. Hardman, D. "Bytewise and Externalized SAIDs." 2024.
[8]: https://dhh1128.github.io/keri-tools

[9]. Hardman, D. "Foreign Artifact Credential."
[9]: https://dhh1128.github.io/keri-tools

[10]. Sporny, M., Longley, D., Sabadello, M., Reed, D., Steele, O., and Allen, C., Eds. "Verifiable Credentials Data Model v2.0." W3C Recommendation.
[10]: https://www.w3.org/TR/vc-data-model-2.0/
