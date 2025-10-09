Verifiable Dossiers
================================================

**Specification Status**: v0.3 Draft

**Latest Draft:**

[https://github.com/trustoverip/kswg-dossier-specification](https://github.com/trustoverip/kswg-dossier-specification)

**Author:**

- [Daniel Hardman](https://github.com/dhh1128), [Provenant](https://provenant.net/)

**Editors:**

**Contributors:**

**Participate:**

~ [GitHub repo](https://github.com/trustoverip/kswg-dossier-specification)
~ [Commit history](https://github.com/trustoverip/kswg-dossier-specification/commits/main)

**Abstract**

This document provides a normative definition for a dossier, a data structure for compiling and attesting to collections of verifiable evidence. A dossier is an Authentic Chained Data Container (ACDC) issued by the party assembling the evidence, functioning as a cryptographically verifiable affidavit rather than a traditional credential. It enables the creation of arbitrarily rich, tamper-evident data graphs of evidence. This specification defines the dossier's data model, its operational lifecycle of curation, citation, and verification, and its underlying security and privacy mechanisms, including graduated disclosure. It provides implementation guidance through detailed use cases in telecommunications, law enforcement, and investigative journalism.

[//]: # (\maketitle)

[//]: # (\newpage)

[//]: # (\toc)

[//]: # (\newpage)

[//]: # (::: forewordtitle)

## Introduction

[//]: # (:::)

### The Challenge of Verifiable Evidence Aggregation
In both the physical and digital realms, critical decisions are rarely based on a single piece of information. Instead, they rely on a collection of disparate evidence, curated to form a coherent whole. A loan officer assembles a file of financial statements, credit reports, and employment verifications to assess creditworthiness; a law enforcement official compiles a case file containing forensic reports, witness statements, and crime scene documentation to build a case. The integrity of the decision depends not only on the validity of the individual pieces of evidence but also on the integrity of the collection itself.

In the digital world, this aggregation process is fraught with challenges. The core problem is the absence of a standardized, cryptographically secure method to aggregate diverse pieces of evidence, attest to the integrity of the collection, and manage its lifecycle in a decentralized and interoperable manner. Existing systems for evidence management are often siloed within proprietary platforms, dependent on centralized trusted parties, or lack the cryptographic guarantees necessary for high-assurance environments. This fragmentation creates friction, inhibits interoperability across domains (e.g., between different jurisdictions or industries), and introduces single points of failure that can be compromised or become unavailable.

### Introducing the Dossier: An Issuer-Centric Evidence Container
This specification introduces the dossier as a solution to these challenges. A dossier is formally defined as an Authentic Chained Data Container (ACDC) that references an arbitrarily rich collection of signed evidence and is issued by the party that assembles it. It is a container designed to create a verifiable data graph from evidentiary artifacts.

A critical distinction separates a dossier from a traditional verifiable credential. A credential typically makes an assertion about a specific subject, or issuee, conferring some right or attribute upon them. A dossier, by contrast, has no issuee. It has only an issuer—the entity that curates the collection. In this sense, a dossier functions more like a notarized affidavit than a passport; the issuer is making a formal, verifiable attestation about the composition and integrity of the evidence collection itself. This issuer-centric model represents a fundamental shift from traditional subject-centric identity paradigms.

The primary purpose of a dossier is to be "built in advance, based on a prediction about what type of evidence might be interesting or valuable". This contrasts with systems that generate proofs just-in-time in response to a specific verifier query. By pre-assembling evidence into a stable, long-lived, and verifiable container, the dossier enables efficient and scalable proof presentation in a wide variety of contexts.

### Relationship to KERI, ACDC, and Verifiable Credentials
The dossier is not a standalone concept; it is deeply rooted in a stack of emerging open standards for decentralized identity. Its technical foundation is the Authentic Chained Data Containers (ACDC) specification, which defines a format for verifiable, chainable data structures.2 ACDCs, in turn, are secured by the Key Event Receipt Infrastructure (KERI), a protocol for decentralized key management that provides secure, rotatable, and auditable Autonomic Identifiers (AIDs).4 The canonical data representation is provided by the Composable Event Streaming Representation (CESR), an encoding format that ensures deterministic serialization for cryptographic operations.[[6]]

Within this ecosystem, it is important to distinguish the dossier from related concepts. A "bespoke ACDC" may also contain custom links to evidence, but it is typically generated just-in-time to answer a specific verifier's query. A dossier, conversely, is a pre-curated collection intended for broader, repeated use. The emergence of the dossier signifies a maturation in the field of decentralized identity. The ecosystem is moving beyond simple, atomic claims about a subject (the role of a traditional credential) to support the creation of complex, curated narratives backed by a body of evidence. This reflects a more nuanced understanding of trust, recognizing that in the real world, assurance is often derived from a holistic evaluation of multiple, interrelated facts. This paradigm shift establishes a new and vital role within digital ecosystems: the "Evidence Curator." This role—which could be filled by an individual managing their own data, a lawyer building a case, a journalist protecting sources, or an automated service—is responsible for the assembly and attestation of evidence collections, and the dossier provides the formal data structure to support this function.

The following table clarifies these distinctions.

Feature | Dossier | ACDC Credential | Bespoke ACDC
--- | --- | --- | ---
Primary Role | Evidence Compilation | Assertion of Entitlement | Just-in-Time Proof
Recipient | No specific 'issuee' | Specific 'issuee' | Specific 'issuee'
Analogy | Affidavit / Case File | License / Passport | Custom-Generated Report
Creation Time | In advance of use | In advance of use | In response to a query
Content Focus | Graph of external evidence | Attributes of the issuee | Subset of existing evidence

## Status of This Memo

Information about the current status of this document, any errata,
and how to provide feedback on it, may be obtained at
[https://github.com/trustoverip/kswg-dossier-specification](https://github.com/trustoverip/kswg-dossier-specification).

## Copyright Notice

This specification is subject to the **OWF Contributor License Agreement 1.0 - Copyright**
available at
[https://www.openwebfoundation.org/the-agreements/the-owf-1-0-agreements-granted-claims/owf-contributor-license-agreement-1-0-copyright](https://www.openwebfoundation.org/the-agreements/the-owf-1-0-agreements-granted-claims/owf-contributor-license-agreement-1-0-copyright).

If source code is included in the specification, that code is subject to the
[Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.txt) unless otherwise marked. In the case of any conflict or
confusion between the OWF Contributor License and the designated source code license within this specification, the terms of the OWF Contributor License MUST apply.

These terms are inherited from the Technical Stack Working Group at the Trust over IP Foundation. [Working Group Charter](https://trustoverip.org/wp-content/uploads/TSWG-2-Charter-Revision.pdf).


## Terms of Use

These materials are made available under and are subject to the [OWF CLA 1.0 - Copyright & Patent license](https://www.openwebfoundation.org/the-agreements/the-owf-1-0-agreements-granted-claims/owf-contributor-license-agreement-1-0-copyright-and-patent). Any source code is made available under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.txt).

THESE MATERIALS ARE PROVIDED “AS IS.” The Trust Over IP Foundation, established as the Joint Development Foundation Projects, LLC, Trust Over IP Foundation Series ("ToIP"), and its members and contributors (each of ToIP, its members and contributors, a "ToIP Party") expressly disclaim any warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to the materials. The entire risk as to implementing or otherwise using the materials is assumed by the implementer and user. 
IN NO EVENT WILL ANY ToIP PARTY BE LIABLE TO ANY OTHER PARTY FOR LOST PROFITS OR ANY FORM OF INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES OF ANY CHARACTER FROM ANY CAUSES OF ACTION OF ANY KIND WITH RESPECT TO THESE MATERIALS, ANY DELIVERABLE OR THE ToIP GOVERNING AGREEMENT, WHETHER BASED ON BREACH OF CONTRACT, TORT (INCLUDING NEGLIGENCE), OR OTHERWISE, AND WHETHER OR NOT THE OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[//]: # (\mainmatter)

[//]: # (\doctitle)

## Scope

Creation of a flexible collection of robustly linked, formally verifiable evidence.


## Normative references

[a]. IETF RFC-2119 Key words for use in RFCs to Indicate Requirement Levels
[a]: https://www.rfc-editor.org/rfc/rfc2119.txt

[b]. Smith, S., Griffin, K., Ed., and Trust Over IP Foundation, "Key Event Receipt Infrastructure (KERI)", January 2024.
[b]: https://trustoverip.github.io/tswg-keri-specification/

[c]. Smith, S., Feairheller, P., Griffin, K., Ed., and Trust Over IP Foundation, "Authentic Chained Data Containers (ACDC)", November 2023.
[c]: https://trustoverip.github.io/tswg-acdc-specification/

[d]. Smith, S., Griffin, K., Ed., and Trust Over IP Foundation, "Composable Event Streaming Representation (CESR)", November 2023.
[d]: https://trustoverip.github.io/tswg-cesr-specification/

[e]. JSON Schema Community, "JSON Schema Specification 2020-12", June 2022.
[e]: https://json-schema.org/specification.


## Terms and Definitions

This specification assumes familiarity with the following core concepts, which are described with a short phrase here but defined normatively in their respective specifications:

* Issuer: An entity that creates and signs a data structure like an ACDC.
* Verifier: An entity that consumes and validates a data structure to make a trust decision.
* Authentic Chained Data Container (ACDC): A verifiable data container format defined in.2
* Self-Addressing Identifier (SAID): A cryptographically generated, content-addressable identifier for a data object, as defined in the ACDC and KERI specifications.1
* Autonomic Identifier (AID): A self-certifying identifier managed via the KERI protocol.1
* Key Event Log (KEL): A verifiable, append-only log of key management events for an AID, as defined in the KERI specification.1
* Edge: A property in the `e` section of an ACDC that binds the ACDC to an external digital artifact by using a hash for (or, in some cases, a digital signature embedded in) that artifact.

In addition the following terms are defined normatively, here:

* Evidentum: A single external artifact that is referenced by an edge. A countable group of these artifacts is pluralized as "evidenta", but is usually referred to with the uncounted, collective form, "evidence".
* Proximate Metdata: Metadata about the dossier as a whole that the issuer of the dossier wishes to directly attest as part of the issuance process.

[//]: # (Dossier Data Model {#sec:content})

## Dossier Data Model (Normative)

### Core Structure: The Dossier as an ACDC

A dossier MUST be a valid Authentic Chained Data Container (ACDC) as defined in the ACDC specification.2

### The Role of the Issuer

The issuer of a dossier is the entity that curates the collection of evidence and attests to its composition by digitally signing the container. The issuer's signature makes a specific, verifiable assertion: at the time of issuance, the collection of evidence referenced within the dossier is the exact collection the issuer intended to present. The issuer does not necessarily attest to the veracity of the claims within the evidence, but rather to the integrity and composition of the collection itself.

### The Edges Attribute: Linking to Evidence

The primary payload of a dossier is not a set of direct claims, but rather a graph of references to external evidence. This graph is contained within an edges block (`e`), as defined in the ACDC specification.[[2]] This block MUST contain a JSON object where each key is a semantic label for an edge, and each value is an object describing the link to the external evidence.

A dossier MAY contain an unbounded number of edges, reflecting its core purpose of aggregating an arbitrary quantity and variety of evidence. The field names (keys) for these edges MAY be any valid JSON string, allowing issuers to provide semantically meaningful labels for the linked evidence (e.g.,
"vettingCredential", "forensicReport_01", "tnAllocationProof"), as demonstrated in the Verifiable Voice Protocol (VVP) specification.

### Base JSON-Schema Definition

To ensure a baseline of interoperability while preserving the flexibility required for diverse use cases, all dossiers MUST conform to a base JSON Schema. This specification defines the normative requirements for such a schema.

A compliant schema for a dossier:

* MUST be composed of an `allOf` array, of which one object is a `$ref` that references the base dossier schema by its SAID, and other objects add additional structure as desired. The `$ref` to the base dossier signals that the schema is for a dossier and should be processed using the dossier semantics defined in this spec. Example:

    ```json
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.org/schemas/acdc-minimum.json",
        "title": "Mortgage Creditworthiness Dossier",
        "description": "Evidence of a borrower's qualification for a mortgage.",
        "properties": {
            "allOf": [
                { 
                    "description": "reference to dossier base schema",
                    "$ref": "EBLnGaNHgEnOvMDqnQO8lpzPQqfZRxC_Rdoinii5buGz" },
                {
                    "type": "object",
                    "description": "add properties unique to this dossier in next obj"
                    "properties": {
                    }
                }
            ]
        }
    }
    ```

* MUST define fields within the ACDC `a` section for proximate metadata.
* MUST use the ACDC `e` section (edges) to bind to the dossier to all evidenta, and MUST NOT place any evidenta in the `a` section.
* MAY include edges that are for traditional ACDC relationships but not for evidenta.
* SHOULD NOT include an issuee field.
* SHOULD set the `additionalProperties` keyword to true at the root level and for the edges object. This is a critical design principle that allows issuers to include arbitrary, application-specific edges without invalidating the dossier against the base schema.

This mandated flexibility has a direct consequence for implementers of verifier systems. A generic dossier verifier can be built to perform universal cryptographic validation—confirming signatures, SAIDs, and KEL consistency—for any dossier conforming to the base schema. However, such a generic verifier cannot be expected to understand the full semantics of every possible dossier. For instance, it can verify that an edge labeled "lunarPropertyDeed" is cryptographically linked, but it cannot know what that means or how to process it. Therefore, verification must be understood as a layered process. The first layer, cryptographic validation, is universal and defined by this specification. The second layer, semantic validation (e.g., "Does this dossier contain a valid TNAlloc credential for the phone number in question?"), is necessarily application-specific and requires context-dependent business logic. This separation allows the dossier format to be a universal building block for evidence aggregation across countless current and future use cases.

## Incorporating Evidence

A dossier's primary function is to serve as a container for references to external evidence. This section defines the normative methods for incorporating both ACDC-native and non-ACDC evidence formats.

### Referencing ACDC-Native Evidence

When a piece of evidence being included in a dossier is itself a valid ACDC (for example, a vettingCredential or a TNAlloc credential as defined in VVP), the corresponding edge in the dossier's edges block MUST reference it by its SAID and the SAID of its schema.

The value of the edge MUST be a JSON object containing at least the following two keys:

* `n`: The SAID of the referenced ACDC. This provides a direct, tamper-evident link to the evidence artifact.
* `s`: The SAID of the schema to which the referenced ACDC conforms. This allows a verifier to correctly parse and interpret the evidence.

This pattern is exemplified by the sample dossier in the VVP specification.

### Referencing Non-ACDC Evidence

To foster broad interoperability, this specification provides mechanisms for incorporating evidence from other verifiable data ecosystems, such as W3C Verifiable Credentials or ISO mDLs.

#### Direct Reference by Signature (Discouraged)

A dossier MAY include an edge that references non-ACDC material directly by its digital signature, without declaring a schema for the content. However, this method is NOT RECOMMENDED.

The rationale for this recommendation is that direct reference places a significant and often untenable burden on the verifier. The verifier must possess the logic to parse and validate the foreign data format, understand its unique lifecycle, and locate its specific revocation mechanism, if one even exists. Such foreign evidence often has "unpredictable lifespans and undefined schemas," making robust, automated verification difficult and brittle.1

#### The ACDC Wrapper Pattern (Recommended)

The normatively RECOMMENDED pattern for including non-ACDC evidence is the "ACDC Wrapper," also referred to as bridging. This pattern externalizes the complexity of handling foreign evidence formats into a dedicated, verifiable attestation.

The process is as follows:

1. A designated entity, hereafter the "bridging party," obtains the non-ACDC evidence.
1. The bridging party verifies the foreign evidence according to its native rules and policies (e.g., validating the signature and semantics of a W3C Verifiable Credential).
1. The bridging party then issues a new, standard ACDC—the wrapper—that makes a specific, verifiable assertion, such as: "I, the bridging party, successfully verified the attached foreign evidence on date X according to policy Y".1
1. This newly created wrapper ACDC is then linked into the dossier using the standard mechanism for ACDC-native evidence described in Section 3.1.

This pattern transforms the problem of verifying a foreign format into the problem of trusting the attestation of the bridging party. While this introduces a new trust consideration, it standardizes the verification process for the dossier's consumer, who now only needs to validate a standard ACDC and assess the reputation of the bridging party. This "trust translation" is a powerful interoperability tool, but it requires careful consideration by verifiers. The verifier's trust in the wrapped evidence is now contingent on the reputation, security practices, and verification policies of the bridging party. Furthermore, the revocation lifecycles of the original foreign evidence and the ACDC wrapper are decoupled unless a specific governance framework explicitly links them. These considerations are explored further in Section 5.

#### Normative Schema for a Generic Evidence Wrapper

To support the ACDC Wrapper pattern, this specification defines the requirements for a generic wrapper ACDC schema. A schema for a generic evidence wrapper MUST include fields to capture:

* The AID of the bridging party (as the issuer of the wrapper).
* The timestamp of the verification event.
* The original foreign evidence, which MAY be embedded directly within the wrapper or referenced via a secure link (e.g., a URL with a hash).

A reference (e.g., a URL) to the verification policy or governance framework that the bridging party followed when validating the foreign evidence.

## The Dossier Lifecycle

The dossier is a persistent data artifact with a distinct lifecycle encompassing three phases: curation, citation, and verification.

### Curation: Assembling and Signing the Dossier

Curation is the process of creating a dossier. This phase is typically performed in advance of any real-time transaction and involves the assembly and attestation of the evidence collection.1

The normative steps for dossier curation are as follows:

1. **Evidence Acquisition**: The entity intending to issue the dossier first acquires the necessary evidence from their respective authoritative sources. For example, a business might obtain a legal entity vetting credential from a qualified issuer, a telephone number allocation credential from its carrier, and a brand credential from a brand vetter.1

2. **Assembly**: The issuer constructs the dossier ACDC data structure. This involves creating an edges block and populating it with named links that point to each acquired evidence artifact, as described in Section 3.

3. **Signing and Anchoring**: The issuer uses the private key(s) associated with its KERI AID to sign the fully assembled dossier ACDC. This act of signing creates a non-repudiable attestation to the dossier's content. The issuance event, including the signature, is then anchored in the issuer's Key Event Log (KEL), providing a permanent, verifiable record.

4. **Publication**: The issuer publishes the signed dossier ACDC at a stable, publicly resolvable location, typically one or more HTTP URLs. This allows authorized verifiers to fetch the dossier when it is cited.1

### Citation: Referencing the Dossier in Protocols

Because dossiers are designed to be stable, long-lived, and potentially large data structures, they are generally not transmitted in their entirety within real-time communication protocols. Instead, they are cited.1

A citation is a reference that allows a verifier to locate and retrieve the full dossier. The normative requirement for a dossier citation is that it MUST be a resolvable identifier that enables a verifier to fetch the complete and unmodified dossier ACDC. The canonical implementation of this is the Out-of-Band Invitation (OOBI) URL used in the evd (evidence) claim of a VVP passport. An OOBI is a specialized URL that points to a resource serving the ACDC and its associated KERI proofs.

### Verification: Algorithm for Validation

Verification is the process by which a recipient of a dossier citation validates the dossier and its entire graph of evidence. The following normative algorithm, generalized from the process described in the VVP specification, outlines the required steps for a compliant verifier.1

The algorithm requires two inputs: the dossier citation and a referenceTime (which may be the current time for real-time validation or a time in the past for historical analysis).

1. **Fetch Dossier**: Resolve the dossier citation (e.g., the OOBI URL) to retrieve the full dossier ACDC.
2. **Validate Dossier Integrity and Signature**:

    1. Calculate the SAID of the retrieved data and verify that it matches the SAID expected from the citation, if available.
    2. Retrieve the issuer's KEL.
    3. Verify the signature on the dossier against the issuer's public key(s) that were authoritative at the referenceTime, as determined by the KEL.

3. **Recursive Graph Traversal and Validation**: For each named edge in the dossier's edges block:

    1. Fetch the referenced evidence artifact (e.g., another ACDC).
    2. Validate the integrity and signature of the artifact in the same manner as the dossier, using its issuer's KEL and the referenceTime.
    3. If the fetched artifact itself contains links to further evidence (e.g., a vetting credential linking to the credential of its issuer), recursively perform this validation step for all nodes in the evidence graph.
   
4. **Check Revocation Status**: For the dossier itself and for every verifiable artifact in its evidence graph, check for any revocation events that are effective as of the referenceTime. This check MUST be performed by consulting the issuer's KEL or a designated status registry specified within the artifact.1
5. **Apply Semantic Rules**: After successful cryptographic validation of the entire evidence graph, the verifier MUST apply any application-specific business logic or policy rules. Examples include: confirming that a TNAlloc credential covers the specific phone number used in a call, or that a delegation credential authorizes the specific action being performed.

This rigorous verification process reveals a key architectural principle of systems using dossiers: the "root of trust" is not a single, centralized entity. Instead, it is a set of issuer AIDs that the verifier must trust for specific types of claims. A verifier of a VVP dossier, for instance, must trust the issuer of the legal entity credential, the telecom regulator that anchors the telephone number allocation chain, and the brand vetter. This decentralizes not only the data but also the trust decisions themselves. Consequently, a critical component of any compliant verifier implementation is a configurable root-of-trust policy.

## Security Considerations

### Integrity and Non-Repudiation via KERI

The security of the dossier model is founded on the cryptographic primitives provided by KERI and ACDC.
Integrity: The integrity of the dossier and all ACDC-native evidence within its graph is guaranteed by the use of Self-Addressing Identifiers (SAIDs). A SAID is a cryptographic hash of an object's canonical content. Any modification to the data, no matter how small, will result in a different SAID, making tampering immediately and computationally evident.1

Non-Repudiation: The act of issuing a dossier is made non-repudiable by the issuer's digital signature. This signature is cryptographically anchored in the issuer's Key Event Log (KEL), which serves as a permanent, publicly auditable, and tamper-evident log of all significant actions taken by the identifier, including issuances, rotations, and revocations.1

### Replay Attack Mitigation in Citation Protocols

The dossier itself is a stable, long-lived artifact designed for reuse. As such, the primary risk of replay attacks exists not at the level of the dossier, but at the level of the protocol that cites it. An attacker could capture a valid citation message and re-submit it in a different context.

To mitigate this, any protocol that cites a dossier MUST incorporate ephemeral, context-specific data into the payload that is cryptographically signed. This data MUST bind the citation to a unique transaction. The VVP passport provides a canonical example of this practice, including the following in its signed JWT payload 1:

* `iat` (Issued At) and exp (Expiration) timestamps to create a narrow window of validity.
orig (originator) and dest (destination) identifiers to bind the call to specific parties.
* `jti` (JWT ID), a unique nonce to prevent identical replays within the validity window.

### Verifier Trust and Root of Trust Management

As established in Section 4.3, the dossier model operates on a decentralized root of trust. A verifier does not rely on a single authority but must make explicit trust decisions about a plurality of evidence issuers. The security of the overall system is therefore contingent on the verifier's ability to manage its trust policies securely.

The foundation of this trust is the KERI protocol's witness infrastructure. Witnesses are independent services that act as notaries for an AID's KEL. By requiring an issuer to report its key events to a set of witnesses, the system gains high availability and, crucially, duplicity detection. If an issuer attempts to present two different versions of its key history to different parties, the discrepancy will be detectable by querying the witnesses. Verifiers SHOULD consult multiple witnesses to ensure they have a consistent and complete view of an issuer's KEL, thereby protecting against duplicity and compromise.1

### Long-Term Auditability and Historical Analysis

A key security feature of the KERI-based dossier ecosystem is its inherent support for robust, long-term auditing. Because KELs provide a complete, verifiable, and sequenced history of an identifier's key state, a verifier can perform validation not just for the present moment, but for any arbitrary point in the past.1

This capability is critical for use cases involving compliance, legal discovery, and post-incident forensic analysis. An auditor can ask not only, "Is this dossier valid now?" but also, "Was this dossier and its entire evidence graph valid at the time of the transaction, based on the key states and revocation information known at that moment?" This provides a level of non-repudiable historical accountability that is difficult or impossible to achieve in systems that rely on ephemeral key state or certificates with fixed expiration dates.

## Privacy Considerations

### Graduated Disclosure Mechanism

Dossiers MUST support privacy-preserving disclosure of their contents through the graduated disclosure mechanism inherent to the ACDC specification. This mechanism is analogous to a Merkle tree. An ACDC is a hierarchical JSON object, and its SAID is computed recursively: the hash of a parent object is derived from its scalar values and the hashes (SAIDs) of its child objects.1

This structure means that any child object within an ACDC can be replaced by its SAID without altering the SAID of the parent object and, critically, without invalidating the digital signature on the entire container. This allows the holder or issuer of a dossier to generate "compacted" or "redacted" versions of the ACDC. These compacted versions can selectively hide sensitive information while remaining cryptographically verifiable. For example, a dossier could link to a full vetting credential containing a legal name and address. For a specific interaction, the holder could present a compacted version of that credential that reveals only the legal name but replaces the address object with its SAID. A verifier can still validate the signature on the credential and confirm that the redacted information exists, without having access to the sensitive address data itself.

### Analysis of Data Correlation Vectors
Even with the use of graduated disclosure, verifiers may be able to correlate a party's activity across multiple transactions by observing persistent identifiers. The primary correlation vectors in a dossier-based protocol are 1:

* Dossier SAID: The SAID of the dossier itself (e.g., as carried in an evd claim) is a unique and persistent identifier for that specific evidence collection, and by extension, its issuer.
* Citation Signer AID: The AID of the entity signing the real-time citation message (e.g., the kid in a VVP passport) can be used to link all messages signed by that same identifier.
* Explicit Brand Information: Any unredacted brand information (e.g., in a card claim) is an obvious and intentional correlator.

### Mitigation Strategies for Unwanted Correlation
Where privacy is a requirement, implementers SHOULD employ strategies to mitigate these correlation vectors.
For the Citation Signer AID: The AID used for signing transactional messages (the kid in VVP) often represents automated software rather than a legal entity. This AID can be rotated frequently without affecting the long-lived AID of the dossier issuer. Furthermore, a service provider signing on behalf of many clients can maintain a pool of AIDs, using different ones for different clients or transactions to provide a degree of herd privacy and break correlation.1

For the Dossier SAID: To break the link between a transaction and a persistent dossier SAID, a trusted third party, or "VP Blinding Service," may be introduced. This service can verify an original dossier and then issue a new, short-lived, derivative dossier. This derivative dossier attests to the validity of the original without revealing its SAID to the end verifier. The verifier trusts the blinding service's attestation. This pattern enhances privacy at the cost of reintroducing a trusted intermediary for a specific function.1

### Contractually Protected Disclosure
Technical privacy mechanisms can be augmented with legal and contractual controls. A server hosting a dossier MAY be configured to enforce access control policies. For example, it could serve a compacted, privacy-preserving version of a dossier to any anonymous request but require a cryptographically signed request to access a more expanded version. The act of signing the request can be tied to the verifier's agreement to a set of terms and conditions regarding data privacy, use, and re-sharing. This approach creates a verifiable audit trail of who accessed sensitive information and contractually binds them to specific data handling policies, combining technical enforcement with legal accountability.1

## Use Cases and Implementation Guidance

### Verifiable Voice Protocol (VVP)

The Verifiable Voice Protocol provides the most complete, end-to-end implementation example for dossiers. In VVP, the dossier serves as the container for all the stable, long-lived evidence that proves an Accountable Party's (AP) identity and right to make a call.

#### Dossier Structure for an Accountable Party (AP)

A typical dossier for a VVP AP would be issued by the AP's AID and contain a set of named edges pointing to the essential credentials for establishing trust in a voice call. An example structure would include 1:

* vetting: An edge to an ACDC (e.g., a verifiable LEI) that proves the legal identity of the AP.
* alloc: An edge to a TNAlloc credential ACDC that proves the AP's right to use the originating phone number.
* brand: An edge to a Brand credential ACDC that proves the AP's right to use asserted brand assets like a name or logo.
* delsig: An edge to a DelegatedSigner credential, used when the AP delegates the real-time signing of call passports to another entity, such as a call center.

#### Example Evidence Graph for Call Center Delegation

In a common business scenario, an enterprise (the AP) hires a call center to make calls on its behalf. The call center's equipment becomes the Originating Party (OP). The dossier is essential for maintaining a verifiable chain of accountability. The evidence graph, starting from the real-time call, would be as follows 1:

1. A verifier receives a SIP INVITE containing a VVP passport signed by the OP's AID (from the kid header).
1. The passport's evd claim points to the AP's dossier.
1. The verifier fetches the dossier and validates its signature from the AP.
1. Inside the dossier, the verifier finds the delsig edge pointing to a DelegatedSigner credential. This credential was issued by the AP to the OP, explicitly authorizing the OP to sign passports on the AP's behalf.
1. The verifier also validates the other edges, such as the vetting credential for the AP and the TNAlloc credential, confirming the AP's identity and right to use the number.

This chained validation proves that the call, though technically originated by the OP, is being made with the explicit, verifiable, and revocable authority of the fully identified and accountable AP.

### Law Enforcement Evidence Management

The dossier concept can be directly applied to the law enforcement use case of managing a digital case file, providing a robust, tamper-evident alternative to traditional systems.1

#### Dossier as a Tamper-Evident Case File

An investigating agency can create a dossier for each case. The dossier's SAID acts as a cryptographic seal on the entire collection of evidence at a specific point in time. As new evidence is collected, the agency can issue a new version of the dossier, including links to the new material. This creates a verifiable, append-only timeline of the case file's evolution, where each stage is sealed and tamper-evident.

#### Linking Witness Statements and Forensic Reports

Much of law enforcement evidence is not born-digital in a verifiable format (e.g., PDFs of lab reports, video files of interviews, scanned documents). The ACDC Wrapper pattern (Section 3.2.2) is the ideal mechanism for incorporating this evidence while preserving a verifiable chain of custody. When a piece of evidence is received, the evidence clerk or responsible officer would create and issue a wrapper ACDC. This wrapper would attest to the fact that "Officer Jane Doe received this specific file (identified by its hash) from this source at this date and time." This wrapper ACDC is then linked into the case dossier, creating a permanent, non-repudiable record of the evidence's entry into custody.

### Investigative Journalism

The dossier provides a powerful new tool for investigative journalists, particularly for managing source material and protecting anonymous sources.

#### Dossier for Source Material Aggregation

A journalist can create a dossier for each investigation. This dossier serves as a private, verifiable compilation of all source materials: interview notes, leaked documents, public records, data sets, etc. Each piece of material can be incorporated using the ACDC Wrapper pattern, creating a timestamped attestation of when the material was obtained. This provides a strong internal record for fact-checking and editorial oversight.

#### Using Graduated Disclosure to Protect Anonymous Sources

The graduated disclosure mechanism (Section 6.1) offers a revolutionary method for source protection. Consider a scenario where a journalist has a statement from an anonymous source, which is captured in an ACDC.

1. The journalist includes a link to this full ACDC in their story's dossier.
1. If the story's veracity is challenged, the journalist can present a compacted version of the dossier to an editor or a court.
1. This compacted version would replace the sensitive source statement ACDC with its SAID.
This act proves, cryptographically, that a source statement existed and was part of the evidence base when the dossier was created. It proves its existence and its role in the investigation without revealing the content of the statement or the identity of the source. This provides a far stronger basis for defending journalistic integrity than a simple verbal assertion, while maintaining the confidentiality required to protect sources from retribution.

[//]: # (\newpage)

[//]: # (\makebibliography)

## Bibliography

[[spec]]

[1]. KERI
[1]: https://trustoverip.github.io/tswg-keri-specification/

[2]. ACDC
[2]: https://trustoverip.github.io/tswg-acdc-specification/

[3]. CESR
[3]: https://trustoverip.github.io/tswg-cesr-specification/

[4]. Verifiable Voice Protocol
[4]: https://www.ietf.org/archive/id/draft-hardman-verifiable-voice-protocol-03.html
