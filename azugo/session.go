package webeidazugo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	webeid "github.com/gmb-lib/go-web-eid"
)

// sessionContextKey is the per-request user-value key under which the opaque
// session identifier is stored by EnsureSession.
const sessionContextKey = "webeid.session_id"

// ErrNoSession is returned by the session-key function when no session has been
// established on the request.
var ErrNoSession = errors.New("no web eid session on request")

// sessionIDBytes is the entropy of an opaque pre-auth session identifier.
const sessionIDBytes = 32

// EnsureSession returns middleware that establishes an anonymous, HttpOnly,
// Secure, SameSite=Strict pre-auth session cookie holding an opaque session ID.
// The ID binds the challenge nonce to the browser it was issued to.
//
// When Configuration.EnforceHostHeader is set (the default) it additionally
// rejects requests whose Host header does not match the configured Origin's
// host — defence-in-depth against DNS rebinding and host-spoofing; the token
// signature already binds the origin cryptographically, this catches mismatch
// earlier and on the non-signed endpoints too.
func EnsureSession(cfg *Configuration) azugo.RequestHandlerFunc {
	cookieName := cfg.SessionCookieName
	ttl := cfg.NonceTTL
	originHosts := originHostnames(cfg.Origins)
	enforceHost := cfg.EnforceHostHeader && len(originHosts) > 0
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if enforceHost && !hostMatchesAny(string(ctx.Request().Header.Host()), originHosts) {
				ctx.Error(errHostMismatch)
				return
			}
			sid := string(ctx.Request().Header.Cookie(cookieName))
			if !validSessionID(sid) {
				newID, err := newSessionID()
				if err != nil {
					ctx.Error(err)
					return
				}
				sid = newID
				setSessionCookie(ctx, cookieName, sid, ttl)
			}
			ctx.SetUserValue(sessionContextKey, sid)
			next(ctx)
		}
	}
}

// errHostMismatch is returned when the request Host header does not match the
// configured site origin.
var errHostMismatch = &hostMismatchError{}

type hostMismatchError struct{}

func (*hostMismatchError) Error() string { return "request host does not match the configured origin" }
func (*hostMismatchError) SafeError() string {
	return "request host does not match the configured origin"
}
func (*hostMismatchError) StatusCode() int { return 400 }

// originHostnames extracts the lower-cased hostnames from the configured origins,
// skipping any that cannot be parsed.
func originHostnames(origins []string) []string {
	hosts := make([]string, 0, len(origins))
	for _, o := range origins {
		if h := originHostname(o); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// hostMatchesAny reports whether the request Host matches any configured origin host.
func hostMatchesAny(requestHost string, originHosts []string) bool {
	for _, oh := range originHosts {
		if hostMatches(requestHost, oh) {
			return true
		}
	}
	return false
}

// originHostname extracts the lower-cased hostname (without port) from the
// configured origin; "" when it cannot be parsed.
func originHostname(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// hostMatches compares a request Host header against the origin hostname,
// ignoring case and any port.
func hostMatches(requestHost, originHost string) bool {
	h := strings.ToLower(strings.TrimSpace(requestHost))
	if h == "" {
		return false
	}
	// Strip a port if present ([::1]:8443, host:443).
	if i := strings.LastIndex(h, ":"); i > -1 && !strings.HasSuffix(h, "]") {
		if !strings.Contains(h[i+1:], "]") {
			h = h[:i]
		}
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return h == strings.TrimSuffix(strings.TrimPrefix(originHost, "["), "]")
}

// SessionKey is the webeid.SessionKeyFunc that reads the session ID established
// by EnsureSession from the request context.
func SessionKey(ctx context.Context) (string, error) {
	c := azugo.RequestContext(ctx)
	if c == nil {
		return "", ErrNoSession
	}
	sid, _ := c.UserValue(sessionContextKey).(string)
	if sid == "" {
		return "", ErrNoSession
	}
	return sid, nil
}

// NewSessionStore returns a session-backed, in-process challenge-nonce store.
// For clustered deployments substitute a TTL-aware external store keyed by the
// same session ID.
func NewSessionStore(cfg *Configuration) webeid.ChallengeNonceStore {
	return webeid.NewInMemoryStore(SessionKey, cfg.NonceTTL)
}

// newSessionID generates an opaque, URL-safe session identifier.
func newSessionID() (string, error) {
	buf := make([]byte, sessionIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// validSessionID performs a cheap structural check on a session identifier.
func validSessionID(sid string) bool {
	if len(sid) == 0 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(sid)
	return err == nil
}

// setSessionCookie writes the secure pre-auth session cookie onto the response.
func setSessionCookie(ctx *azugo.Context, name, value string, ttl time.Duration) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey(name)
	cookie.SetValue(value)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSecure(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteStrictMode)
	if ttl > 0 {
		cookie.SetMaxAge(int(ttl.Seconds()))
	}
	ctx.Response().Header.SetCookie(cookie)
}
