package browser

// Form auto-fill and event triggering, adapted from projectdiscovery/katana
// (MIT License, https://github.com/projectdiscovery/katana —
// pkg/utils/formfill.go and pkg/engine/headless/crawler/formfill.go) and
// reimplemented on go-rod. Value rules follow katana: an existing value or
// placeholder is kept, otherwise the input type picks a value; radio and
// checkbox are clicked instead of typed.
//
// Every interaction here is gated behind explicit configuration
// (browser.auto_form / trigger_events) because submitting forms and clicking
// buttons can trigger the target's own write paths.

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// defaultMaxInteractions bounds form submits plus event clicks per render.
const defaultMaxInteractions = 20

// interactionWait is the grace period after one interaction so the request
// it fires reaches the CDP recorders before the next one.
const interactionWait = 700 * time.Millisecond

// interactOnce runs the enabled interaction passes over one rendered page
// and returns how many interactions were performed. seen carries form and
// element signatures across the whole scan so repeated views are skipped.
func (c *Collector) interactOnce(
	page *rod.Page,
	seen map[string]struct{},
) int {
	budget := c.config.MaxInteractions
	if budget <= 0 {
		budget = defaultMaxInteractions
	}
	used := 0
	if c.config.AutoForm {
		used += c.fillAndSubmitForms(page, seen, budget)
	}
	if c.config.TriggerEvents {
		if remaining := budget - used; remaining > 0 {
			used += c.clickInteractiveElements(page, seen, remaining)
		}
	}
	return used
}

// fillAndSubmitForms fills every form on the current page and submits it.
// All forms are filled before the first submit: a submission may navigate
// away, which invalidates the remaining element handles.
func (c *Collector) fillAndSubmitForms(
	page *rod.Page,
	seen map[string]struct{},
	limit int,
) int {
	forms, err := page.Elements("form")
	if err != nil || len(forms) == 0 {
		return 0
	}
	type pendingForm struct {
		form      *rod.Element
		submit    *rod.Element
		signature string
		filled    int
	}
	pending := make([]pendingForm, 0, len(forms))
	for _, form := range forms {
		if len(pending) >= limit {
			break
		}
		signature, filled := c.fillForm(form)
		if filled == 0 {
			continue
		}
		if _, done := seen[signature]; done {
			continue
		}
		seen[signature] = struct{}{}
		pending = append(pending, pendingForm{
			form: form, signature: signature, filled: filled,
			submit: findSubmitButton(form),
		})
	}
	submitted := 0
	for _, item := range pending {
		if submitted >= limit {
			break
		}
		if c.submitForm(item.form, item.submit) {
			submitted++
			_ = waitShort(page, interactionWait)
		}
	}
	return submitted
}

// fillForm fills one form's controls per the katana rules and returns a
// stable signature plus how many controls accepted a value. In aggressive
// mode disabled controls are filled too, through direct DOM writes.
func (c *Collector) fillForm(form *rod.Element) (string, int) {
	controls, err := form.Elements("input, textarea, select")
	if err != nil {
		return "", 0
	}
	filled := 0
	signature := fnv.New64a()
	for _, control := range controls {
		attributes := describeControl(control)
		_, _ = signature.Write([]byte(
			attributes.Tag + "\x00" + attributes.Type + "\x00" + attributes.Name + "\x00"))
		if attributes.Disabled && !c.config.Aggressive {
			continue
		}
		if interactControl(c.config.Aggressive, control, attributes) {
			filled++
		}
	}
	return fmt.Sprintf("form%x", signature.Sum64()), filled
}

type controlInfo struct {
	Tag         string
	Type        string
	Name        string
	ID          string
	Placeholder string
	Value       string
	Disabled    bool
}

// describeControl reads the attributes a fill decision needs. Element handles
// can vanish mid-walk (re-rendering views), so any failure just skips it.
func describeControl(control *rod.Element) controlInfo {
	info := controlInfo{Tag: "input"}
	read := func(js string) string {
		value, err := control.Eval(js)
		if err != nil {
			return ""
		}
		return value.Value.Str()
	}
	if tag := read("() => this.tagName"); tag != "" {
		info.Tag = strings.ToLower(tag)
	}
	info.Type = strings.ToLower(read("() => this.type"))
	info.Name = read("() => this.name")
	info.ID = read("() => this.id")
	info.Placeholder = read("() => this.placeholder")
	info.Value = read("() => this.value")
	info.Disabled = read("() => String(this.disabled)") == "true"
	return info
}

// interactControl applies one katana-style value: select options are chosen,
// checkbox/radio clicked, everything else typed through rod so framework
// change listeners fire.
func interactControl(aggressive bool, control *rod.Element, info controlInfo) bool {
	switch info.Tag {
	case "select":
		options, err := control.Elements("option")
		if err != nil || len(options) == 0 {
			return false
		}
		// Set the first option and fire change so framework listeners see it;
		// a synthetic mouse click cannot open a <select> dropdown.
		_, err = control.Eval(`() => {
			if (!this.options.length) return;
			this.selectedIndex = 0;
			this.dispatchEvent(new Event('change', {bubbles: true}));
		}`)
		return err == nil
	case "textarea":
		return inputOrDOM(aggressive, control, info) == nil
	}
	switch info.Type {
	case "checkbox", "radio", "submit", "button", "image", "reset", "file":
		if info.Type == "checkbox" || info.Type == "radio" {
			if control.Click(proto.InputMouseButtonLeft, 1) == nil {
				return true
			}
			// Disabled/covered elements reject real clicks; aggressive mode
			// still toggles them through the DOM.
			if aggressive {
				_, err := control.Eval("() => { this.checked = !this.checked;" +
					" this.dispatchEvent(new Event('change', {bubbles: true})) }")
				return err == nil
			}
			return false
		}
		return false
	}
	return inputOrDOM(aggressive, control, info) == nil
}

// inputOrDOM types the value through rod so framework listeners fire, and in
// aggressive mode falls back to a direct DOM write when the control is
// disabled, readonly, or hidden.
func inputOrDOM(aggressive bool, control *rod.Element, info controlInfo) error {
	value := fillValue(info)
	if value == "" {
		return nil
	}
	if inputText(control, value) == nil {
		return nil
	}
	if aggressive {
		return setValueViaJS(control, value)
	}
	return errors.New("input rejected")
}

// setValueViaJS writes a value through the DOM and dispatches the events
// frameworks listen for. It reaches controls real interaction cannot:
// disabled, readonly, and display:none inputs.
func setValueViaJS(control *rod.Element, value string) error {
	_, err := control.Eval(`(v) => {
		this.value = v;
		this.dispatchEvent(new Event('input', {bubbles: true}));
		this.dispatchEvent(new Event('change', {bubbles: true}));
	}`, value)
	return err
}

func inputText(control *rod.Element, value string) error {
	if value == "" {
		return nil
	}
	return control.Input(value)
}

// findSubmitButton locates the form's submit control, katana-style: an
// explicit submit input, then a submit button, then any button.
func findSubmitButton(form *rod.Element) *rod.Element {
	for _, selector := range []string{
		"input[type=submit]", "button[type=submit]", "button", "input[type=button]",
	} {
		if buttons, err := form.Elements(selector); err == nil && len(buttons) > 0 {
			return buttons[0]
		}
	}
	return nil
}

// submitForm clicks the submit control, falling back to form.submit(). It
// reports whether an action was actually taken.
func (c *Collector) submitForm(form, submit *rod.Element) bool {
	if submit != nil {
		if err := submit.Click(proto.InputMouseButtonLeft, 1); err == nil {
			return true
		}
	}
	_, err := form.Eval("() => this.submit()")
	return err == nil
}

// clickInteractiveElements clicks buttons and inline-handler elements so SPA
// interactions fire their hidden API calls. Element-level guards mirror
// katana: skip disabled, invisible, and already-visited controls, and stop
// dead when a click navigated away (stale handles after that).
func (c *Collector) clickInteractiveElements(
	page *rod.Page,
	seen map[string]struct{},
	limit int,
) int {
	elements, err := page.Elements("button, [onclick], [role=button], a[href='#']")
	if err != nil {
		return 0
	}
	clicked := 0
	for _, element := range elements {
		if clicked >= limit {
			break
		}
		info := describeControl(element)
		key := fmt.Sprintf("click:%s:%s:%s", info.Tag, info.Name, info.ID)
		if _, done := seen[key]; done {
			continue
		}
		seen[key] = struct{}{}
		if info.Disabled && !c.config.Aggressive {
			continue
		}
		if err := element.ScrollIntoView(); err != nil && !c.config.Aggressive {
			continue
		}
		if !c.config.Aggressive {
			if visible, err := element.Visible(); err != nil || !visible {
				continue
			}
		}
		before, _ := page.Eval("() => location.href")
		if err := element.Click(proto.InputMouseButtonLeft, 1); err != nil {
			// Covered or detached elements reject synthetic clicks; in
			// aggressive mode a DOM click() still fires inline handlers.
			if !c.config.Aggressive {
				continue
			}
			if _, jsErr := element.Eval("() => this.click()"); jsErr != nil {
				continue
			}
		}
		clicked++
		_ = waitShort(page, interactionWait)
		after, err := page.Eval("() => location.href")
		if err == nil && after != nil && before != nil &&
			before.Value.Str() != after.Value.Str() {
			break // navigated away: remaining handles are stale
		}
	}
	return clicked
}

func waitShort(_ *rod.Page, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	<-timer.C
	return nil
}

// fillValue picks the value for one control. Adapted from katana's
// FormFillSuggestions with two JsOwl adjustments: tel gets a valid-looking
// Chinese mobile number (the targets this tool hunts are CN apps), and the
// name/id keyword table covers the account-login shapes katana leaves to the
// generic placeholder.
func fillValue(info controlInfo) string {
	if info.Value != "" {
		return "" // keep the page's own value: it is already valid input
	}
	if info.Placeholder != "" {
		return info.Placeholder
	}
	hint := strings.ToLower(info.Name + " " + info.ID)
	switch info.Type {
	case "email":
		return "jsowl@example.org"
	case "password":
		return "JsOwlP@ssw0rd1"
	case "tel":
		return "13800138000"
	case "number", "range":
		return "1"
	case "date":
		return "2026-01-01"
	case "search", "text", "":
		for keyword, value := range keywordFillValues {
			if strings.Contains(hint, keyword) {
				return value
			}
		}
		return "jsowl"
	}
	return "jsowl"
}

var keywordFillValues = map[string]string{
	"phone":   "13800138000",
	"mobile":  "13800138000",
	"mail":    "jsowl@example.org",
	"user":    "jsowl",
	"account": "jsowl",
	"name":    "jsowl",
	"code":    "123456",
	"captcha": "123456",
	"idcard":  "110101199001011234",
	"search":  "jsowl",
}
