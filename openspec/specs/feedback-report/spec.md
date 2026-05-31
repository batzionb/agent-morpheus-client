# feedback-report Specification

## Purpose
Structured feedback on completed repository reports, submitted via REST and forwarded to an external feedback service.

## Requirements

### Requirement: Feedback Card Content
The Feedback card (`FeedbackReportCard`) SHALL appear after Additional Details on completed repository report pages with title "Feedback" and subtitle "Your feedback will be used to improve the accuracy of our AI models."

#### Scenario: Card placement and labels
- **WHEN** a user views a completed repository report page
- **THEN** the Feedback card appears with the title and subtitle above

### Requirement: Feedback Form Fields
The card SHALL collect required Accuracy, Reasoning, Checklist dropdowns and 1–5 Rating (asterisk-marked), plus optional Comment. Submit Feedback SHALL stay disabled until all required fields are set, then enable as primary.

#### Scenario: Required fields and submit state
- **WHEN** a user views the Feedback card
- **THEN** required dropdowns and rating block submit until filled; comment remains optional

### Requirement: Frontend API Usage
The card SHALL use generated client only: `postApiV1Feedback` for submit and `getApiV1FeedbackExists` for existence check. Body SHALL conform to `Feedback`. When feedback exists, show already-submitted state instead of the form.

#### Scenario: Submit and already-submitted flows
- **WHEN** the user submits valid feedback
- **THEN** `postApiV1Feedback` is called (no direct fetch/axios) with optional `comment`
- **WHEN** `getApiV1FeedbackExists` returns exists true on load
- **THEN** the already-submitted state replaces the form

### Requirement: Backend Feedback Processing
The backend SHALL expose POST `/api/v1/feedback` and GET `/api/v1/feedback/{reportId}/exists`, forward to the external feedback service (not persisted locally), return `{"status":"success"}` on submit success, `{"exists":true|false}` on exists check, and HTTP 500 with JSON error on external failure.

#### Scenario: Backend submit and exists flows
- **WHEN** POST `/api/v1/feedback` receives a valid body
- **THEN** FeedbackService forwards to the external API and returns 200 on success or 500 on failure
- **WHEN** GET `/api/v1/feedback/{reportId}/exists` is called
- **THEN** the backend returns 200 with `exists` true or false, or 500 on external failure
