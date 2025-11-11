# User Personas for IoTSentinel

**Created**:
**Purpose**: Define target users to guide UX design and requirements

---

## Persona 1: "The Concerned Parent" - Sarah

### Demographics

- **Name**: Sarah Mitchell
- **Age**: 42
- **Occupation**: Secondary School Teacher
- **Location**: Suburban home, Belfast
- **Tech Proficiency**: Low-Medium (uses smartphone, basic computer skills)
- **Household**: Married, 2 children (ages 10 and 14)

### Technology Context

- **Devices at Home**:
  - 2x Laptops (work and personal)
  - 4x Smartphones (family)
  - 1x Smart TV
  - 2x Tablets (children's devices)
  - 1x Amazon Echo
  - 1x Ring doorbell

### Goals & Motivations

1. **Primary Goal**: Protect children from online threats
2. **Secondary Goal**: Monitor family's device usage
3. **Aspiration**: Understand what her devices are doing without technical jargon

### Pain Points

- "I get too many confusing security alerts from my router"
- "I don't know if my children are visiting dangerous websites"
- "Security products are either too expensive or too complicated"
- "I want to learn about cybersecurity, but most tools don't explain anything"

### Frustrations with Current Solutions

- **Bitdefender BOX**: "It tells me something is blocked, but not WHY"
- **Router Admin Panel**: "I tried logging in once - gave up after 5 minutes"
- **Antivirus Software**: "Pop-ups are annoying and I don't understand them"

### Quote

> "I just want to know if someone is doing something bad on our network, and I want to understand what's happening in plain English."

### Success Criteria for IoTSentinel

- ✅ Can identify all family devices within 5 minutes
- ✅ Receives alerts she can understand without Googling terms
- ✅ Can explain to her husband what an alert means
- ✅ Feels empowered, not overwhelmed

---

## Persona 2: "The Tech-Curious Homeowner" - David

### Demographics

- **Name**: David Chen
- **Age**: 38
- **Occupation**: Graphic Designer (works from home)
- **Location**: Townhouse, London
- **Tech Proficiency**: Medium-High (comfortable with tech, not a programmer)
- **Household**: Lives with partner, no children

### Technology Context

- **Devices at Home**:
  - 3x Laptops/desktops (work machines)
  - 2x Smartphones
  - 1x NAS (Synology for backup)
  - 2x Smart speakers
  - 1x Smart thermostat (Nest)
  - 3x Smart bulbs
  - 1x Security camera
  - 1x Gaming console

### Goals & Motivations

1. **Primary Goal**: Understand his home network security
2. **Secondary Goal**: Learn about cybersecurity concepts
3. **Aspiration**: Become more tech-savvy without formal training

### Pain Points

- "Commercial products are 'black boxes' - I want to see HOW they work"
- "I'm willing to learn, but documentation is either too basic or too advanced"
- "I don't want to pay £99/year for something I can't customize"
- "I want transparency: show me the data, show me the algorithm"

### Frustrations with Current Solutions

- **Firewalla**: "Too many features I don't need, interface is overwhelming"
- **DIY Solutions**: "I tried pfSense - gave up after 3 hours"
- **Commercial Products**: "Why can't they just tell me what the ML model is seeing?"

### Quote

> "I don't need it dumbed down, but I also don't need a PhD. Just explain the 'why' behind every decision."

### Success Criteria for IoTSentinel

- ✅ Understands what "anomaly detection" actually means
- ✅ Can see which features triggered an alert (with explanations)
- ✅ Feels like he's learning security concepts through use
- ✅ Can confidently discuss home network security with friends

---

## Persona 3: "The Budget-Conscious User" - Margaret

### Demographics

- **Name**: Margaret O'Brien
- **Age**: 55
- **Occupation**: Retired Nurse
- **Location**: Small flat, Manchester
- **Tech Proficiency**: Low-Medium (uses iPad daily, cautious with tech)
- **Household**: Lives alone, frequent grandchildren visits

### Technology Context

- **Devices at Home**:
  - 1x Laptop (rarely used)
  - 1x iPad (primary device)
  - 1x Smartphone
  - 1x Smart TV
  - 1x Wireless printer

### Goals & Motivations

1. **Primary Goal**: Avoid subscription fees (fixed income)
2. **Secondary Goal**: Feel safe online without spending money
3. **Aspiration**: Not be a burden on her son (who handles her tech issues)

### Pain Points

- "I can't afford £10/month for security software"
- "I worry about online banking security"
- "My grandson's devices might be unsafe when he visits"
- "I don't want to call my son every time I get a security warning"

### Frustrations with Current Solutions

- **Subscription Costs**: "£99/year is my entire monthly grocery budget"
- **Complexity**: "Setup required a phone call to my son"
- **Trust**: "How do I know the security company isn't spying on me?"

### Quote

> "I'm on a pension. I need something that works, costs nothing after I buy it, and doesn't require a computer science degree."

### Success Criteria for IoTSentinel

- ✅ One-time hardware cost only (Raspberry Pi ~£50)
- ✅ No recurring subscription fees
- ✅ Setup simple enough to do with written instructions
- ✅ Clear alerts that don't require technical support calls

---

## Design Implications

### From Sarah (Concerned Parent)

- **Implication 1**: Alerts MUST use plain language (no "TCP SYN flood")
- **Implication 2**: Dashboard must show device names, not IP addresses
- **Implication 3**: Color coding (red/yellow/green) for quick status checks
- **Implication 4**: Educational tooltips for every technical term

### From David (Tech-Curious)

- **Implication 1**: "Show Your Work" - explain which features caused alert
- **Implication 2**: Provide access to raw data (CSV export, API)
- **Implication 3**: Documentation should explain ML concepts clearly
- **Implication 4**: Allow customization of detection thresholds

### From Margaret (Budget-Conscious)

- **Implication 1**: Emphasize "No subscription" in all marketing
- **Implication 2**: Setup wizard must be foolproof (max 10 steps)
- **Implication 3**: Provide written quick-start guide (large font)
- **Implication 4**: Minimal ongoing maintenance required

---

## Persona Usage in Development

### Requirements Phase (AT2)

- Map each user story to a specific persona
- Example: "As **Sarah**, I want to see device names..."

### Design Phase (AT3)

- Test UI designs against persona expectations
- Example: Would David find this explanation satisfying?

### Testing Phase (Usability)

- Recruit participants matching persona profiles
- Example: Find 2 non-technical parents for testing

### Evaluation Phase (AT3)

- Measure success against persona-specific criteria
- Example: Did Sarah complete device identification in < 5 minutes?

---

## Anti-Personas (Who We're NOT Targeting)

### Anti-Persona: "The Enterprise IT Admin"

- **Why**: Needs features like SIEM integration, compliance reporting
- **IoTSentinel Limitation**: Designed for home use, not enterprise

### Anti-Persona: "The Privacy Extremist"

- **Why**: Wants zero data collection, even locally
- **IoTSentinel Limitation**: Requires monitoring to function

### Anti-Persona: "The Advanced Hacker"

- **Why**: Wants full packet captures, manual rule writing
- **IoTSentinel Limitation**: Educational tool, not penetration testing platform

---
