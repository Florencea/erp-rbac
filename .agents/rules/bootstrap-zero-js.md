---
trigger: glob
globs: "web/**, internal/web/**"
description: Strict Bootstrap 5 CSS-only constraints, zero JavaScript enforcement, and HTML accessibility standards.
---

# Bootstrap 5 CSS-Only and Zero JavaScript Rules

## Allowed Assets and Styling

- Link only `/static/bootstrap.min.css` in templates.
- Never add custom `.css` files, `<style>` blocks, inline `style="..."` attributes, or CSS preprocessors.
- Use only class names defined in `web/static/bootstrap.min.css`. For indentation or spacing, use discrete Bootstrap utilities (`ps-0` through `ps-5`).
- All dynamic class additions must be covered by `internal/web/lint_test.go`.

## Zero JavaScript Policy

- Never add `<script>` tags, external `.js` bundles (including `bootstrap.bundle.min.js`), inline event handlers (`onclick=`, `onchange=`, `onsubmit=`, etc.), or `javascript:` URIs.
- Never use Bootstrap JavaScript trigger attributes (`data-bs-toggle`, `data-bs-dismiss`, `data-bs-target`, `data-bs-ride`, `data-bs-slide`).
- Replace modals, drawers, and confirmation dialogs with dedicated GET/POST pages using Post-Redirect-Get (`303 See Other`).
- Keep `script-src 'none'` active in `Content-Security-Policy`.

## HTML5 Accessibility

- Set `lang="{{.Lang}}"` on `<html>`.
- Include landmark elements (`<header>`, `<nav aria-label="...">`, `<main>`).
- Pair every non-hidden, non-submit `<input>`, `<select>`, and `<textarea>` with a `<label for="...">` or `aria-label`.
- Mark active navigation links with `aria-current="page"`.
- Use `<th scope="col">` for all table header cells and `role="alert"` for status/error banners.
- Mark invalid form controls with `.is-invalid`, `aria-invalid="true"`, and `<div class="invalid-feedback d-block">`.
