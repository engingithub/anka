# Headless Web II: OIDC Authentication and Authority-Aware Access

## Why this matters

The original headless-web experiment was our proof that the system was **alive**: it could exist as a networked logical node, expose a direct endpoint, maintain context, invoke Kleis/Z3, and return verified results without depending on a conventional chat UI.

The next proof of life is stronger:

> **It is alive -> it knows who is talking to it and what they may ask it to do.**

The next milestone is therefore:

> **Headless Web II: authenticated and authority-aware logical node**

The first headless-web milestone proved:

> **It is alive.**

The second should prove:

> **It knows who you are, and it does not confuse who you are with what you are allowed to do.**

---

## Authentication: OIDC answers "Who are you?"

Use OpenID Connect to establish an authenticated principal:

```text
browser/client
    -> OIDC provider
    -> ID/access token
    -> headless node
    -> authenticated principal
```

The durable external identity should not be an email address or display name. The natural identity key is:

```text
PrincipalId = (issuer, subject)
```

because `sub` is meaningful only within an issuer.

A login/session incarnation can remain a separate concept if needed later.

---

## Authorization: roles and scopes are not the same thing

Treat roles and scopes as distinct architectural concepts.

A **role** answers:

> **What policy class does this principal belong to?**

A **scope** answers:

> **What authority is being presented for this operation?**

Possible early roles:

```text
researcher
operator
```

Possible early scopes:

```text
kleis.verify
kleis.submit
context.read
node.inspect
node.admin
```

The authorization check should not be merely:

```text
is_authenticated(user)
```

or even:

```text
user.role == "researcher"
```

It should be closer to:

```text
PresentedAuthority(token) >= RequiredAuthority(operation)
```

where `>=` means "contains at least the required authority."

---

## Minimal proof-of-concept API

A small first test surface could be:

```text
/alive         public
/whoami        requires authenticated OIDC principal
/verify        requires kleis.verify
/submit        requires kleis.submit
/admin/status  requires operator role or node.admin authority
```

Hostile tests should include:

```text
valid identity, missing scope          -> 403
right scope, wrong audience            -> 401
expired token                          -> 401
wrong issuer                           -> 401
researcher attempts operator endpoint  -> 403
```

Keep the distinction explicit:

```text
401 = principal cannot be established
403 = principal established, presented authority insufficient
```

---

## The bridge from Anka to OAuth/OIDC

Anka is teaching us that identity and authority must be separated.

The same abstraction can apply to:

```text
human
process
driver
service
AI agent
    -> principal
```

A principal does not receive ambient privilege merely because of who it is. It receives explicitly named, attenuated authority for particular operations.

Current Anka concepts have natural web analogues:

| Anka | Headless Web / OAuth |
|---|---|
| `ProcessKey` | principal/session incarnation |
| `CapabilityHandle` | presented authorization handle/token |
| `AuthorityId` | live authorization/grant instance |
| `DelegationId` | grant/delegation provenance |
| `DeviceRights` | OAuth scopes |
| `ObjectId` | protected resource / audience |
| `SYS_DEV_SUBMIT` | protected API operation |

This suggests a single underlying authorization algebra for:

```text
CPUs
DMA engines
drivers
processes
services
AI agents
humans
```

Different principals and interfaces, but the same laws of authority.

---

## The crucial security rule: exact presented authority

The strongest lesson from Anka 9.2c is:

> **Ambient privilege must not rescue an insufficient presented authority.**

For a device driver:

```text
H_buffer
    -> exact buffer authority
    -> DMA authority
```

For the web:

```text
H_OAuth
    -> exact presented authority
    -> API operation
```

If a user or application has broad account privileges elsewhere but presents a token scoped only to:

```text
kleis.verify
```

then that request does **not** acquire `node.admin` merely because the same human or application could obtain broader authority through another path.

The protected operation should be justified by the authority actually presented for that request.

---

## OAuth as delegation, not just login

OIDC establishes:

> **Who are you?**

OAuth-style authorization establishes:

> **What authority are you presenting?**

The longer-term Anka/Kleis question becomes:

> **Why is that authority valid, where did it come from, and was it attenuated correctly?**

This opens the door to explicit delegation chains such as:

```text
Alice
  -> Assistant
    -> Travel Service
      -> Airline
```

There are then two different questions:

> **May you do this?**

and:

> **Why do you have the authority to do this?**

That mirrors the Anka distinction:

```text
AuthorityId  = what live authority instance is this?
DelegationId = where did this authority come from?
```

A future web authorization layer may eventually preserve authenticated delegation provenance rather than only immediate scopes.

---

## Design principle

Treat people the same way we are learning to treat device drivers:

- identity is not authority;
- authority is explicit;
- authority is attenuated;
- authority is bound to a resource/audience;
- authority is tied to an incarnation/lifetime;
- delegation must not amplify authority;
- stale identities must not silently alias new principals;
- revocation must invalidate future use;
- the authority actually presented must justify the operation;
- provenance and authorization are related but distinct.

This is the conceptual bridge from the Anka OS architecture to OIDC/OAuth and eventually to human/service/agent authorization.

---

## AI agents as user-space drivers

A future AI agent should be treated architecturally the same way Anka treats a user-space device driver: as an **untrusted principal that may perform useful work only through explicitly delegated authority**.

The model is:

```text
User
  -> narrow task delegation
    -> AgentInstance
      -> exact presented authority
        -> tool / service / resource
```

The agent's intelligence, model identity, prompt, alignment, or relationship to the user does **not** confer ambient authority.

The central rule is inherited directly from Anka:

> **Ambient authority must not rescue an insufficient presented capability.**

Thus, if an agent is delegated authority to read one document, a broader service credential available elsewhere must not allow that particular operation to expand into reading the entire drive.

The protected operation should be justified by the authority actually presented for that operation:

```text
H_task
    -> exact task authority
    -> tool / API operation
```

This is the AI-agent analogue of Anka's:

```text
H_buffer
    -> exact buffer authority
    -> DMA authority
```

### Agent identity should be incarnation-qualified

The model itself is not necessarily the durable principal. A running agent should have an incarnation-qualified identity analogous to `ProcessKey`:

```text
AgentInstanceKey = (agent identity, incarnation/session)
```

This prevents an authorization intended for an old agent instance from silently attaching to a newly created one.

Authorization should distinguish:

- **identity** — who/what is acting?
- **capability** — what may this operation do?
- **AuthorityId** — which live grant justifies it?
- **DelegationId** — where did that authority come from?
- **resource generation** — is the target still the same incarnation?

### Multi-agent delegation

For delegation chains such as:

```text
Human
  -> Agent A
    -> Agent B
      -> Service
```

authority must attenuate monotonically at every hop:

```text
A0 ⊇ A1 ⊇ A2 ⊇ ... ⊇ An
```

No agent may invent authority.

This means the system should be able to distinguish:

> **May you do this?**

from:

> **Why do you have the authority to do this?**

The first is an authorization question. The second is a provenance question.

### Systems-level AI safety rule

This suggests a systems-level formulation of AI safety:

> **Do not ask whether the agent is trusted. Ask what exact authority it presented for this exact operation.**

The same authorization algebra can therefore govern:

```text
humans
services
LLMs
autonomous agents
processes
device drivers
DMA engines
```

Different principals and interfaces; the same laws of authority.


---

## Host-controlled networking is another authority boundary

The user-space NIC work adds a useful distinction for the future headless web
node: **permission to produce a virtual Ethernet frame is not permission to use
the host's physical network**.

Anka's guest-side authority chain ends at a committed finite NIC operation:

```text
presented NIC_TX capability
  + presented Memory.READ capability
  -> exact finite Fabric READ
  -> committed virtual-NIC frame
```

What happens next is emulator/host policy:

```text
virtual NIC frame
  -> HostNicBackend
  -> {loopback, synthetic peer, future external bridge}
```

Conversely, host-provided input first enters bounded NIC-private state:

```text
Host RX offer
  -> explicit host injection
  -> private RX queue + event epoch
  -> presented NIC_RX + Memory.WRITE
  -> finite Fabric WRITE
  -> guest memory
```

Therefore neither direction creates an ambient shortcut around the authority
model:

```text
GuestTx(frame)  != authority to transmit on the physical host network
HostInject(frame) != direct guest-memory authority
```

A future externally bridged headless node should keep this split.  OIDC/OAuth
answers which remote principal may request an application operation; Anka
capabilities authorize the resulting local resource/device operations; host
network policy determines whether a virtual frame is allowed to leave the
emulator.  These are related enforcement layers, not one universal "trusted"
bit.

---

## Future milestone

After Phase 9.2 stabilizes, return to the headless web and implement:

1. OIDC authentication.
2. `PrincipalId = (issuer, sub)`.
3. Generation/session-aware principal identity if needed.
4. Scope-based operation authorization.
5. Optional role-based policy.
6. Audience/resource binding.
7. Exact-presented-authority enforcement.
8. 401/403 hostile tests.
9. Later: delegation provenance analogous to `DelegationId`.

The goal is not merely:

> "The web node has login."

The goal is:

> **The node authenticates principals and reasons explicitly about delegated authority.**
