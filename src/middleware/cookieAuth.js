'use strict';

/**
 * Central definition of the auth cookie. The token is stored ONLY in this
 * httpOnly cookie (never in a JSON body or localStorage), so browser JavaScript
 * — and therefore XSS payloads or a pasted DevTools console command — cannot
 * read or steal it.
 *
 * `res.cookie` / `res.clearCookie` are built into Express, so no extra
 * dependency (cookie-parser) is required; reading is done by hand in auth.js.
 */

const AUTH_COOKIE = 'tm_token';
const TWELVE_HOURS_MS = 12 * 60 * 60 * 1000; // matches JWT_EXPIRES_IN default (12h)

// Frontend (:3000) and backend (:4000) share the same host, so they are the SAME
// site (ports don't affect "site") — SameSite=Lax is honoured on the cross-port
// fetch. `secure` is enabled only in production (HTTPS); over plain-HTTP dev it
// must stay false or the browser silently refuses to store the cookie.
function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  };
}

function setAuthCookie(res, token) {
  res.cookie(AUTH_COOKIE, token, { ...cookieOptions(), maxAge: TWELVE_HOURS_MS });
}

function clearAuthCookie(res) {
  res.clearCookie(AUTH_COOKIE, cookieOptions());
}

module.exports = { AUTH_COOKIE, setAuthCookie, clearAuthCookie };
