# Verifiable Dossiers

**Specification Status**: v0.6 Draft

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
In both the physical and digital realms, critical decisions are rarely based on a single piece of information. Instead, decision makers rely on a collection of disparate evidence, curated to form a coherent whole. A loan officer assembles a file of financial statements, credit reports, and employment verifications to assess creditworthiness; a law enforcement official compiles a case file containing forensic reports, witness statements, and crime scene documentation to build a case. The confidence of the decision depends not only on the validity of the individual pieces of evidence but also on the integrity of the collection itself.

In the digital world, this aggregation process is fraught with challenges. The core problem is the absence of a standardized, cryptographically secure method that aggregates diverse pieces of evidence, attests to the integrity of the collection, and manages its lifecycle in a decentralized and interoperable manner. Existing systems for evidence management are often siloed within proprietary platforms, dependent on centralized trusted parties, or lack the cryptographic guarantees necessary for high-assurance environments. This fragmentation creates friction, inhibits interoperability across domains (e.g., between different jurisdictions or industries), and introduces single points of failure that can be compromised or become unavailable.

### Evidence Lifespans and Verification Timing

A second observation shapes the dossier design: the evidence underlying real-world decisions has wildly different lifespans, and the parties who later verify that evidence are usually not in contact with the signer at the moment of verification.

Some evidence is **temporary**. A movie ticket, a JSON Web Token, a browser session cookie, or a transient network message carries authority for seconds or minutes — just long enough to complete a single interaction in a controlled environment.

Other evidence is **changed occasionally**. A PIN, a password, a credit-card number, an X.509 certificate, or a magnetic key card carries a secret that the holder rotates on a scale of days to months as it expires or is suspected of compromise.

A third class is **effectively permanent**. A birth certificate, a passport, articles of incorporation, a fingerprint or iris template, or a chain-of-custody record on a piece of forensic evidence anchors a fact that is meant to be relied on for years or decades.

A dossier inhabits the permanent end of this spectrum. It snapshots evidence that the issuer expects to remain meaningful and verifiable long after issuance, in front of audiences and against questions the issuer cannot anticipate at signing time. Verifiers may consume a dossier indirectly: an auditor reviewing a loan years after funding, a court evaluating a chain of custody decades after collection, an insurance adjuster reconstructing facts about an incident years before the claim. None of these verifiers communicates with the issuer at the moment of verification.

This asynchronous, indirect verification model has three direct consequences for the dossier design:

1. **The artifact must stand alone.** Verification cannot depend on a live channel back to the issuer at verification time.
2. **Recency and freshness vary per evidentum.** A bank balance referenced in a mortgage dossier may need to be less than a week old; an LEI vetting may be acceptable up to a year old; a passport scan may be acceptable for the document's full validity period. The dossier model accommodates these mixed timelines through per-edge metadata and Temporal Pinning, not through a single global expiry.
3. **State must be reconstructible at an arbitrary historical point.** Verification at time T requires the key state, revocation state, and evidence state that were effective at T — not necessarily at the moment of verification. This is supported by KERI's historical-query capability over its KELs.

### Introducing the Dossier: An Issuer-Centric Evidence Container
This specification introduces the dossier as a solution to these challenges. A dossier is formally defined as an Authentic Chained Data Container (ACDC) that references an arbitrarily rich collection of signed evidence and is issued by the party that assembles it. It is a container designed to create a verifiable data graph from evidentiary artifacts.

A critical distinction separates a dossier from a traditional verifiable credential. A credential typically makes an assertion about a specific subject, or issuee, conferring some right or attribute upon them. A dossier, by contrast, has no issuee. It has only an issuer—the entity that curates the collection. In this sense, a dossier functions more like a notarized affidavit than a passport; the issuer is making a formal, verifiable attestation about the composition and integrity of the evidence collection itself. This issuer-centric model represents a fundamental shift from traditional subject-centric identity paradigms.

The primary purpose of a dossier is to empower decisions that are likely to be made based on the attested collection of evidence it includes. This contrasts with systems that generate proofs just-in-time in response to a specific verifier query. By pre-assembling evidence into a stable, long-lived, and verifiable container, the dossier enables efficient and scalable proof presentation in a wide variety of contexts.

### Relationship to KERI, ACDC, and Verifiable Credentials
The dossier is not a standalone concept; it is deeply rooted in a stack of emerging open standards for decentralized identity. Its technical foundation is the Authentic Chained Data Containers (ACDC) specification, which defines a format for verifiable, chainable data structures.2 ACDCs, in turn, are secured by the Key Event Receipt Infrastructure (KERI), a protocol for decentralized key management that provides secure, rotatable, and auditable Autonomic Identifiers (AIDs).4 The canonical data representation is provided by the Composable Event Streaming Representation (CESR), an encoding format that ensures deterministic serialization for cryptographic operations.[[6]]

Within this ecosystem, it is important to distinguish the dossier from related concepts, including a conventional ACDC credential or a "bespoke ACDC". A bespoke ACDC may also contain custom links to evidence, but it is a direct response to a specific verifier's query. A dossier, by contrast, is a pre-curated collection assembled in anticipation of presenting to arbitrary parties at arbitrary points in time. Timing is a consequence of this difference, not the cause of it: a dossier is created in advance because it must be, given that its intended audience is unknown.

The emergence of the dossier signifies a maturation in the field of decentralized identity. The ecosystem is moving beyond simple, atomic claims about a subject (the purpose of a traditional credential) to support the creation of complex, curated narratives backed by a body of evidence. This reflects a more nuanced understanding of trust, recognizing that in the real world, assurance is often derived from a holistic evaluation of multiple, interrelated facts. This paradigm shift establishes a new and vital role within digital ecosystems: the "Evidence Curator." This role—which could be filled by an individual managing their own data, a lawyer building a case, a journalist protecting sources, or an automated service—is responsible for the assembly and attestation of evidence collections, and the dossier provides the formal data structure to support this function.

The following table clarifies these distinctions.

Feature | Dossier | ACDC Credential | Bespoke ACDC
--- | --- | --- | ---
Primary Role | Evidence Compilation | Assertion of Entitlement | Just-in-Time Proof
Recipient | No specific 'issuee' | Specific 'issuee' | Specific 'issuee'
Analogy | Affidavit / Case File | License / Passport | Custom-Generated Report
Creation Time | In advance of use | In advance of use | In response to a query
Content Focus | Graph of external evidence | Attributes of the issuee | Subset of existing evidence

### Relationship to W3C Verifiable Presentations

Readers familiar with the W3C Verifiable Credentials Data Model [[10]] may see a surface resemblance between a dossier and a Verifiable Presentation (VP). Both are cryptographically verifiable containers of evidence presented in support of a decision. They solve different problems, however, and the differences are worth making explicit.

Aspect | Dossier (ACDC-based) | Verifiable Presentation (W3C VC)
--- | --- | ---
Core role | Cryptographically verifiable container of evidence | Cryptographically verifiable container of credentials
Interoperability model | Wraps or bridges multiple evidence formats, including VCs | Native to the VC ecosystem; interoperable within that model
Primary actor | Curator (often the issuer) attests to the composition of the evidence collection | Holder presents credentials about a subject
Subject model | No issuee; may describe arbitrary parties, events, or facts | Subject-centric; in practice typically the holder
Payload structure | Graph of references (edges) to heterogeneous evidence | Flat bundle (usually VCs) responding to a proof request
Lifecycle | Pre-curated, persistent, versioned, cacheable artifact | Ephemeral, generated per request or interaction
Evidence flexibility | Files, ACDCs, foreign credentials, and wrapped artifacts; supports chained trust | Flexible in theory; in practice limited to VCs and similar credentials
Trust semantics | "This is the complete evidence set I assembled" | "I possess valid credentials proving these claims"

The most consequential practical difference is lifecycle. A VP is created in response to a verifier's request, signed by the holder, presented once, and discarded; if the same holder is asked again later, a new VP is generated. A dossier is assembled in advance, signed by the curator (not the subject), published at a stable location, and referenced repeatedly across many verifiers and many transactions.

A second practical difference is the relationship to the subject. A VP is fundamentally a statement by a subject about themselves: "I hold these credentials." A dossier has no issuee. It is a statement by a curator about a body of evidence: "I assembled these artifacts about this matter, and here is the cryptographic record of that act." Many dossier use cases — a criminal investigation, a journalistic exposé, an audit report — do not have a single subject in the VC sense at all.

These differences do not put the two models in opposition. A dossier MAY reference a W3C VC as one of its evidence items through the bridging mechanism described under *Bridging from Foreign Credential Ecosystems*. The two artifacts solve adjacent problems and can interoperate where their use cases overlap.

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

This specification defines the data model, lifecycle, and verification semantics for verifiable dossiers — cryptographically attested collections of evidence structured as Authentic Chained Data Containers (ACDCs). It is intended for software developers building on the KERI/ACDC ecosystem, standards authors defining protocols that cite or depend on dossiers, enterprise architects designing evidence workflows, and legal or regulatory professionals evaluating the trust guarantees of dossier-based systems.

The following are in scope: normative requirements for dossier structure and schema; joint issuance, operator semantics, and revocation; privacy-preserving and graduated disclosure; and non-normative implementation guidance through use case profiles.

The following are explicitly out of scope: transport or citation protocols for presenting dossiers at transaction time; storage and hosting requirements for dossier artifacts; the internal data formats of evidence items referenced by a dossier; and the KERI, ACDC, and CESR specifications on which this document depends.

## Normative references

[a]. IETF RFC-2119 Key words for use in RFCs to Indicate Requirement Levels
[a]: https://www.rfc-editor.org/rfc/rfc2119.txt

[b]. Smith, S., Griffin, K., Ed., and Trust Over IP Foundation, "Key Event Receipt Infrastructure (KERI)", January 2024.
[b]: https://trustoverip.github.io/kswg-keri-specification/

[c]. Smith, S., Feairheller, P., Griffin, K., Ed., and Trust Over IP Foundation, "Authentic Chained Data Containers (ACDC)", November 2023.
[c]: https://trustoverip.github.io/kswg-acdc-specification/

[d]. Smith, S., Griffin, K., Ed., and Trust Over IP Foundation, "Composable Event Streaming Representation (CESR)", November 2023.
[d]: https://trustoverip.github.io/kswg-cesr-specification/

[e]. JSON Schema Community, "JSON Schema Specification 2020-12", June 2022.
[e]: https://json-schema.org/specification.

