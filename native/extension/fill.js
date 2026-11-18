// This self-contained function runs only in the selected tab's isolated world.
export function fillLogin(expectedOrigin, username, password) {
  if (window.top !== window || location.origin !== expectedOrigin || location.protocol !== 'https:') return false
  const visible = input => !input.disabled && !input.readOnly && input.getClientRects().length > 0 &&
    getComputedStyle(input).visibility === 'visible' && getComputedStyle(input).display !== 'none' && input.autocomplete !== 'new-password'
  const passwords = Array.from(document.querySelectorAll('input[type="password"]')).filter(visible)
  if (passwords.length !== 1) return false
  const field = passwords[0]
  const form = field.form
  if (form && new URL(form.action || location.href, location.href).origin !== expectedOrigin) return false
  const scope = form || document
  const candidates = Array.from(scope.querySelectorAll('input')).filter(input => visible(input) &&
    ['text', 'email', 'tel'].includes(input.type))
  const named = candidates.filter(input => input.autocomplete === 'username' || input.autocomplete === 'email' ||
    /^(user(name)?|email|login)$/i.test(input.name))
  const user = named.length === 1 ? named[0] : candidates.length === 1 ? candidates[0] : null
  // Reject ambiguous forms rather than place a secret into the wrong field.
  if (!user) return false
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set
  setter.call(user, username); setter.call(field, password)
  for (const input of [user, field]) {
    input.dispatchEvent(new Event('input', { bubbles: true }))
    input.dispatchEvent(new Event('change', { bubbles: true }))
  }
  return true
}
