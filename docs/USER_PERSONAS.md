# User Personas for IoTSentinel (v2.1 - Aligned)

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

- **Devices at Home**: 2x Laptops, 4x Smartphones, 1x Smart TV, 2x Tablets, 1x Amazon Echo, 1x Ring doorbell

### Goals & Motivations

1.  **Primary Goal**: Protect children from online threats.
2.  **Secondary Goal**: Understand what her devices are doing without technical jargon.
3.  **Aspiration**: Feel in control of her home's digital safety.

### Pain Points

- "I get too many confusing security alerts from my router."
- "I don't know if my children's devices are talking to something dangerous."
- "Security products are either too expensive or too complicated."
- "I want to learn, but most tools don't explain anything."

### Quote

> "I just want to know if someone is doing something bad on our network, and I want to understand what's happening in plain English."

### Success Criteria for IoTSentinel

- ✅ Can identify all family devices on the dashboard (US-001).
- ✅ Receives alerts she can understand without Googling terms (US-003, US-004).
- ✅ Can see patterns in alerts over time (US-007).
- ✅ Can take direct action, like blocking a device (US-015).
- ✅ Feels empowered, not overwhelmed.

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

- **Devices at Home**: 3x Laptops/desktops, 2x Smartphones, 1x NAS (Synology), 2x Smart speakers, 1x Smart thermostat, 3x Smart bulbs, 1x Security camera.

### Goals & Motivations

1.  **Primary Goal**: Understand his home network's behavior and security.
2.  **Secondary Goal**: Learn about cybersecurity concepts through a practical tool.
3.  **Aspiration**: See the data and understand _how_ the system works.

### Pain Points

- "Commercial products are 'black boxes' - I want to see HOW they work."
- "I'm willing to learn, but documentation is either too basic or too advanced."
- "I want transparency: show me the data, show me the algorithm's logic."

### Quote

> "I don't need it dumbed down, but I also don't need a PhD. Just explain the 'why' behind every decision."

### Success Criteria for IoTSentinel

- ✅ Can see live network traffic in real-time (US-002).
- ✅ Understands _why_ an alert was triggered via explanations (US-004).
- ✅ Can see visual patterns, like the device heatmap (US-006).
- ✅ Can see the ML model's performance metrics (US-010).
- ✅ Can export raw data for his own analysis (US-013).

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

- **Devices at Home**: 1x Laptop (rarely used), 1x iPad (primary device), 1x Smartphone, 1x Smart TV.

### Goals & Motivations

1.  **Primary Goal**: Avoid subscription fees (fixed income).
2.  **Secondary Goal**: Feel safe online without spending money.
3.  **Aspiration**: Not be a burden on her son (who handles her tech issues).

### Pain Points

- "I can't afford £10/month for security software."
- "I worry about online banking security."
- "I don't want to call my son every time I get a security warning."

### Quote

> "I'm on a pension. I need something that works, costs nothing after I buy it, and doesn't require a computer science degree."

### Success Criteria for IoTSentinel

- ✅ One-time hardware cost only (Raspberry Pi).
- ✅ No recurring subscription fees.
- ✅ Setup is simple via an Onboarding Wizard (US-018).
- ✅ The dashboard is fast and responsive on her iPad (US-008, US-017).
- ✅ Can pause monitoring if she feels it's necessary (US-011).

---

## Persona 4: "The System Administrator" - (Technical Persona)

### Demographics

- **Name**: (Internal Persona)
- **Occupation**: Developer / System Operator
- **Tech Proficiency**: High (Creator of the system)

### Technology Context

- **Devices**: Development machine, Raspberry Pi, test devices.

### Goals & Motivations

1.  **Primary Goal**: Ensure the system is stable, reliable, and performant.
2.  **Secondary Goal**: Create a robust baseline for the ML models.
3.  **Aspiration**: Build a system that runs without constant intervention.

### Pain Points

- "The ML model is useless if it's trained on bad 'normal' data."
- "I can't debug the system if I don't know its resource usage."
- "If the capture process (Zeek) dies, the whole system stops working."

### Quote

> "The user-facing features don't matter if the backend isn't stable. I need to monitor system health and ensure the ML training is correct."

### Success Criteria for IoTSentinel

- ✅ Can initiate and monitor a 7-day baseline training period (US-005).
- ✅ Can see system health (CPU, RAM, Disk) on the dashboard (US-012).
- ✅ The system has an orchestrator to auto-restart failed processes (US-012/FR-015).

---

## Design Implications (Updated)

### From Sarah (Concerned Parent)

- **Implication 1**: Alerts MUST use plain language (US-003, US-004).
- **Implication 2**: Dashboard must show device names, not IPs (US-001).
- **Implication 3**: Clear action buttons (Block, Acknowledge) (US-014, US-015).
- **Implication 4**: Educational tooltips for every technical term.

### From David (Tech-Curious)

- **Implication 1**: "Show Your Work" - explain _why_ an alert fired (US-004).
- **Implication 2**: Provide access to raw data (US-013 Export).
- **Implication 3**: Dashboard must visualize data (Heatmap, Timeline) (US-006, US-007).
- **Implication 4**: Show ML performance and threat intel data (US-010, US-019).

### From Margaret (Budget-Conscious)

- **Implication 1**: Emphasize "No Subscription" and one-time cost.
- **Implication 2**: Setup wizard must be foolproof (US-018).
- **Implication 3**: UI must be fast and responsive, especially on mobile/tablet (US-008, US-017).
- **Implication 4**: Features must be intuitive (e.g., "Pause" button) (US-011).

### From System Administrator (Technical)

- **Implication 1**: A separate "System" tab is needed for health metrics (US-012).
- **Implication 2**: Baseline collection must be a clear, separate process (US-005).
- **Implication 3**: Backend processes must be resilient (FR-015 Orchestrator).

---

## Persona Usage in Development

### Requirements Phase (AT2)

- Map each user story (US-001 to US-020) to a primary persona.
- Example: "As **Sarah** (US-003), I want to receive alerts..."
- Example: "As **System Administrator** (US-005), I want to collect..."

### Design Phase (AT3)

- Test UI designs against persona expectations.
- Example: Would David find this explanation satisfying? Is this button clear for Margaret?

### Testing Phase (Usability)

- Recruit participants matching persona profiles.
- Example: Find 2 non-technical users (Sarah/Margaret) for usability testing.

### Evaluation Phase (AT3)

- Measure success against persona-specific criteria.
- Example: Did Sarah understand the alert? Did David find the ML metrics?

---

## Anti-Personas (Who We're NOT Targeting)

- **"The Enterprise IT Admin"**: Needs features like SIEM integration, compliance reporting. IoTSentinel is for home use.
- **"The Privacy Extremist"**: Wants zero data collection. IoTSentinel _requires_ local network monitoring to function.
- **"The Advanced Hacker"**: Wants full packet captures and manual rule writing. IoTSentinel is an educational/alerting tool, not a forensics platform.
