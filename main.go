package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"gopkg.in/ldap.v3"
)

var port = flag.String("port", "5000", "port to listen for HTTP auth requests.")

const (
	AuthStatus    = "Auth-Status"
	AuthUser      = "Auth-User"
	AuthPass      = "Auth-Pass"
	AuthMethod    = "Auth-Method"
	XLdapURL      = "X-Ldap-URL"
	XLdapBaseDN   = "X-Ldap-BaseDN"
	XLdapBindDN   = "X-Ldap-BindDN"
	XLdapBindPass = "X-Ldap-BindPass"
	AuthServer    = "Auth-Server"
	AuthPort      = "Auth-Port"
)

func authFailed(w http.ResponseWriter, err string) {
	log.Printf("Failed authentication due to: %s", err)
	w.Header().Add(AuthStatus, err)
	w.WriteHeader(http.StatusOK)
}

type LdapCredential struct {
	ldapAddr string
	baseDn   string
	bindDn   string
	bindPwd  string
	usr      string
	pwd      string
	domain   string
}

func authViaLdap(cred *LdapCredential) (bool, error) {
	l, err := ldap.DialURL(cred.ldapAddr)
	if err != nil {
		log.Printf("Failed to connect to LDAP server: %s", cred.ldapAddr)
		return false, err
	}
	defer l.Close()
	err = l.Bind(cred.bindDn, cred.bindPwd)
	if err != nil {
		log.Printf("Unable to bind to LDAP server with DN: %s, Pass: %s.", cred.bindDn, cred.bindPwd)
		return false, err
	}

	sreq := ldap.NewSearchRequest(
		cred.baseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", cred.usr),
		[]string{"dn"},
		nil,
	)
	sresp, err := l.Search(sreq)
	if err != nil {
		log.Printf("Search error: %v", err)
		return false, err
	}

	if len(sresp.Entries) != 1 {
		log.Printf("Unable to locate user: %s", cred.usr)
		return false, err
	}

	err = l.Bind(sresp.Entries[0].DN, cred.pwd)
	if err != nil {
		log.Printf("Unable to authenticate user: %s with password: %s", cred.usr, cred.pwd)
		return false, err
	}

	return true, nil
}

func handleHttpAuthReq(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received authentication request: %s", r.Header)
	authm := r.Header.Get(AuthMethod)
	if authm != "plain" {
		authFailed(w, fmt.Sprintf("Unsupported authentication method %s", authm))
		return
	}

	authserver := r.Header.Get(AuthServer)
	authport := r.Header.Get(AuthPort)
	if authserver == "" || authport == "" {
		authFailed(w, "Must supply Auth-Server and Auth-Port via HTTP Header.")
		return
	}

	authud := strings.Split(r.Header.Get(AuthUser), "@")
	if len(authud) != 2 {
		authFailed(w, "Username must contain both user id and domain.")
		return
	}

	cred := LdapCredential{
		usr:      authud[0],
		domain:   authud[1],
		pwd:      r.Header.Get(AuthPass),
		ldapAddr: r.Header.Get(XLdapURL),
		baseDn:   r.Header.Get(XLdapBaseDN),
		bindDn:   r.Header.Get(XLdapBindDN),
		bindPwd:  r.Header.Get(XLdapBindPass),
	}

	success, err := authViaLdap(&cred)
	if !success {
		authFailed(w, fmt.Sprintf("Unable to authenticate user: %s with password %s. error = %v", cred.usr, cred.pwd, err))
		return
	}
	w.Header().Set(AuthStatus, "OK")
	w.Header().Set(AuthServer, authserver)
	w.Header().Set(AuthPort, authport)
	w.WriteHeader(http.StatusOK)
	log.Print("Authentication was successful.")
}

func main() {
	flag.Parse()

	http.HandleFunc("/", handleHttpAuthReq)
	log.Fatal(http.ListenAndServe(":"+*port, nil))
}
