package gopush

import "testing"

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"code.google.com/p/go.net/websocket"
)

const adminTemplateString = `
{
	"formID": "{{.FormID}}",
	"nonce": "{{.Nonce}}",
	"apitokens" : [
	{{range .APITokens}}
	{
		"mail": "{{.Mail}}",
		"pubkey": "{{.PublicKey|js}}"
	},
	{{end}}
	{}
	]
}
`

const adminAddTemplateString = `{{.Key}}`

var port = 18080

const adminUser = "admin"
const adminPass = "admin"

var (
	dbuser = flag.String("mysqluser", "", "MySQL username.")
	dbpass = flag.String("mysqlpass", "", "MySQL Password.")
	dbname = flag.String("mysqldbname", "", "MySQL database name.")
)

func sign(data string, prikey *rsa.PrivateKey) string {
	h := sha1.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	s, err := rsa.SignPKCS1v15(rand.Reader, prikey, crypto.SHA1, digest)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(s)
}

func startDummyServer(config Config, t *testing.T) *GoPushService {
	return startServer(config, NewDummyBackend(), t)
}

func startServer(config Config, backend Backend, t *testing.T) *GoPushService {
	admintpl, _ := template.New("admin").Parse(adminTemplateString)
	adminaddtpl, _ := template.New("adminadd").Parse(adminAddTemplateString)
	svc := NewService(config, backend, &StandardOutputManager{
		AdminTemplate:    admintpl,
		AdminAddTemplate: adminaddtpl,
	})
	if svc == nil {
		return nil
	}
	go svc.Start()

	return svc
}

func startBasicDummyServer(t *testing.T) *GoPushService {
	config := getBaseConfig()
	return startDummyServer(config, t)
}

func startTimeoutDummyServer(t *testing.T) *GoPushService {
	config := getBaseConfig()
	config.Timeout = 2
	return startDummyServer(config, t)
}

func startRedirectingDummyServer(t *testing.T) *GoPushService {
	config := getBaseConfig()
	config.RedirectMainPage = "http://google.com"
	return startDummyServer(config, t)
}

func getBaseConfig() Config {
	return Config{
		Address:          fmt.Sprintf("localhost:%d", port),
		AdminUser:        adminUser,
		AdminPass:        adminPass,
		Timeout:          0,
		UserCache:        true,
		BroadcastBuffer:  4096,
		ExtraLogging:     false,
		RedirectMainPage: "",
	}
}

func getRawPath(path, proto string) string {
	return fmt.Sprintf("%s://localhost:%d/%s", proto, port, path)
}

func getPath(path string) string {
	return getRawPath(path, "http")
}

func getBody(resp *http.Response) string {
	respbody, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	return string(respbody)
}

func getAdmin(path string, t *testing.T) *http.Response {
	req, err := http.NewRequest("GET", getPath(path), nil)
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(adminUser, adminPass)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func postAdmin(path string, body string, t *testing.T) *http.Response {
	req, err := http.NewRequest("POST", getPath(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(adminUser, adminPass)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func postService(path string, body string, key *rsa.PrivateKey, t *testing.T) *http.Response {
	req, err := http.NewRequest("POST", getPath(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	signature := sign(body, key)
	req.Header.Set("Authorization", "GoPush "+signature)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func getAdminMainPage(t *testing.T) adminPageData {
	resp := getAdmin("admin", t)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Invalid response returned from /admin, status code: %d\n", resp.StatusCode)
	}

	body := getBody(resp)

	var page adminPageData
	err := json.Unmarshal([]byte(body), &page)
	if err != nil {
		t.Fatal(err)
	}

	return page
}

func testAdminAdd(mail string, t *testing.T) *rsa.PrivateKey {
	page := getAdminMainPage(t)

	resp := postAdmin("admin/add", fmt.Sprintf("mail=test@example.com&publickey=&nonce=%s&formid=%s", page.Nonce, page.FormID), t)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to add new user, status code: %d\n", resp.StatusCode)
	}

	privkey := getBody(resp)
	if pkey := stringToPrivateKey(privkey); pkey != nil {
		return pkey
	}

	return nil
}

func testAdminList(t *testing.T) {
	page := getAdminMainPage(t)
	if len(page.APITokens) < 1 || page.APITokens[0].Mail != "test@example.com" {
		t.Fatalf("Saved APIToken is not on the admin page.\n")
	}
}

func testAdminRemove(t *testing.T) {
	page := getAdminMainPage(t)

	resp := postAdmin("admin/remove", fmt.Sprintf("mail=test@example.com&nonce=%s&formid=%s", page.Nonce, page.FormID), t)

	if resp.StatusCode != http.StatusFound { // The delete page redirects.
		t.Fatalf("Failed to remove account, code: %d\n", resp.StatusCode)
	}
}

func testAdminListEmpty(t *testing.T) {
	page := getAdminMainPage(t)
	if len(page.APITokens) > 1 { // An empty item is there at the end because of a JSON serialization hack.
		t.Fatalf("The account list is not empty. Number of items: %d\n", len(page.APITokens)-1)
	}
}

func testNotificationCenterCreation(key *rsa.PrivateKey, t *testing.T) string {
	centername := genRandomHash(128)
	resp := postService("newcenter?mail=test@example.com", centername, key, t)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create notification center, code: %d\n", resp.StatusCode)
	}

	return centername
}

func testNotificationSending(key *rsa.PrivateKey, t *testing.T, centername string, shouldSucceed bool) string {
	var resp *http.Response
	testmsg := genRandomHash(128)
	resp = postService("notify?mail=test@example.com&center="+centername, testmsg, key, t)

	if shouldSucceed {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to send a notification, code: %d\n", resp.StatusCode)
		}
	} else {
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("Successfully sent notification.\n")
		}
	}

	return testmsg
}

func testNotificationWithPing(key *rsa.PrivateKey, t *testing.T, centername string, shouldSucceed bool) {
	testmsg := testNotificationSending(key, t, centername, shouldSucceed)

	resp, err := http.DefaultClient.Get(getPath("ping?center=" + getCenterName("test@example.com", centername)))
	if err != nil {
		t.Fatal(err)
	}

	if shouldSucceed {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to ping, code: %d\n", resp.StatusCode)
		}

		body := getBody(resp)
		if body != testmsg {
			t.Fatalf("Message retrieval through ping is failed. Expected: '%s', got: '%s'\n", testmsg, body)
		}
	} else {
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("Ping succeeded.\n")
		}
	}
}

func testNotificationWithWebsocket(key *rsa.PrivateKey, t *testing.T, centername string, shouldSucceed bool) {
	// Connect to host with websockets
	wsconn, err := websocket.Dial(getRawPath("listen?center="+getCenterName("test@example.com", centername), "ws"), "", getPath(""))
	if err != nil {
		t.Fatal(err)
	}

	testmsg := testNotificationSending(key, t, centername, shouldSucceed)

	// The buffer needs to be bigger than the message, to make sure that a longer message won't get mistaken to the original.
	// For example if the test message is "aaa" and the result would be "aaab"
	buf := make([]byte, len(testmsg)+1)
	n, err := wsconn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	wsconn.Close()

	// The buffer is bigger, and the trailing bytes are not needed.
	result := string(buf[:n])

	if testmsg != result {
		t.Fatalf("Message retrieval through websocket is failed. Expected: '%s', got: '%s'\n", testmsg, result)
	}
}

func testNotificationCenterRemoval(key *rsa.PrivateKey, t *testing.T, centername string) {
	var resp *http.Response

	resp = postService("removecenter?mail=test@example.com", centername, key, t)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to remove notification center, code: %d\n", resp.StatusCode)
	}

	resp, err := http.DefaultClient.Get(getPath("ping?center=" + getCenterName("test@example.com", centername)))
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Notification center still exists, code: %d\n", resp.StatusCode)
	}
}

func fullFunctionalTest(t *testing.T) {
	key := testAdminAdd("test@example.com", t)
	if key == nil {
		t.Fatal("Invalid key")
	}

	testAdminList(t)
	centername := testNotificationCenterCreation(key, t)
	testNotificationWithPing(key, t, centername, true)
	testNotificationWithWebsocket(key, t, centername, true)
	testNotificationCenterRemoval(key, t, centername)
	testAdminRemove(t)
	testAdminListEmpty(t)
}

func testWithServer(startfunc func(*testing.T) *GoPushService, t *testing.T, test func(*testing.T)) {
	svc := startfunc(t)
	if svc == nil {
		t.Fatal(svc)
	}
	defer func() {
		svc.Stop()
		port++
	}()
	<-time.After(time.Second)

	test(t)
}

func TestBasicFunctional(t *testing.T) {
	testWithServer(startBasicDummyServer, t, fullFunctionalTest)
}

func TestTimeoutFunctional(t *testing.T) {
	testWithServer(startTimeoutDummyServer, t, func(t *testing.T) {
		key := testAdminAdd("test@example.com", t)
		if key == nil {
			t.Fatal("Invalid key")
		}

		centername := testNotificationCenterCreation(key, t)
		<-time.After(2 * time.Second)
		testNotificationWithPing(key, t, centername, false)
	})
}

func TestRedirectMainPage(t *testing.T) {
	testWithServer(startRedirectingDummyServer, t, func(*testing.T) {
		resp, err := http.DefaultClient.Get(getPath(""))
		if err != nil {
			t.Fatal(err)
		}

		// If the redirection is not set, the main page is http.StatusNotFound.
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Redirection is failed. Code: %d\n", resp.StatusCode)
		}
	})
}

func TestTestFunction(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		key := testAdminAdd("test@example.com", t)
		if key == nil {
			t.Fatal("Invalid key")
		}

		testmsg := genRandomHash(128)

		resp := postService("test?mail=test@example.com", testmsg, key, t)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to reach test service. Code: %d\n", resp.StatusCode)
		}

		respbody := getBody(resp)

		if testmsg != respbody {
			t.Fatalf("Test service result is valid. Expected: '%s', got: '%s'\n", testmsg, respbody)
		}
	})
}

func TestInvalidAdminCredentials(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		testfunc := func(path, data, message string) {
			var resp *http.Response
			var err error
			if data == "" {
				resp, err = http.DefaultClient.Get(getPath(path))
			} else {
				resp, err = http.DefaultClient.Post(getPath(path), "application/x-www-form-urlencoded", strings.NewReader(data))
			}
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s enables unauthorized access. Code: %d\n", message, resp.StatusCode)
			}
		}

		testfunc("admin", "", "Admin listing panel")
		testfunc("admin/add", "mail=test@example.com&publickey=", "Admin user creation page")
		testfunc("admin/remove", "mail=test@example.com", "Admin user remove page")
	})
}

func TestInvalidRequestMethods(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		if resp := postAdmin("admin", "", t); resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST is allowed on main admin page. Code: %d\n", resp.StatusCode)
		}

		if resp := getAdmin("admin/add", t); resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET is allowed on admin user add page. Code %d\n", resp.StatusCode)
		}

		if resp := getAdmin("admin/remove", t); resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET is allowed on admin user remove page. Code %d\n", resp.StatusCode)
		}
	})
}

func TestCSRFProtection(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		if resp := postAdmin("admin/add", "mail=test@example.com&publickey=", t); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CSRF attack is possible on admin user add page. Code: %d\n", resp.StatusCode)
		}

		if resp := postAdmin("admin/remove", "mail=test@example.com", t); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("CSRF attack is possble on admin user remove page. Code: %d\n", resp.StatusCode)
		}
	})
}

func TestServiceMethodAccepting(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		testfunc := func(path, message string) {
			resp, err := http.DefaultClient.Get(getPath(path))
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("%s accepts non-POST request. Code: %d\n", message, resp.StatusCode)
			}
		}

		testfunc("newcenter", "Notification center creation page")
		testfunc("notify", "Notification sending page")
		testfunc("removecenter", "Notification center removal page")
	})
}

func TestMissingParameters(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(*testing.T) {
		key := testAdminAdd("test@example.com", t)

		if resp := postService("newcenter", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Possible to create a notification center without email. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("notify", "", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Possible to send a notification without email. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("notify?mail=test@example.com", "", key, t); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Possible to send a notification to missing center. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("removecenter", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Possible to delete a notification center without email. Code: %d\n", resp.StatusCode)
		}
	})
}

func TestNoSignature(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		testfunc := func(path, data, message string) {
			resp, err := http.DefaultClient.Post(getPath(path), "text/plain", strings.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s can accept messages without signature. Code: %d\n", message, resp.StatusCode)
			}
		}

		testfunc("newcenter", "", "Notification center creation page")
		testfunc("notify", "", "Notify page")
		testfunc("removecenter", "", "Notification center removal page")
		testfunc("test", "", "Test page")
	})
}

func TestInvalidSignature(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		stringpkey, _, err := genKeyPair(1024)
		if err != nil {
			t.Fatal(err)
		}
		key := stringToPrivateKey(stringpkey)
		if key == nil {
			t.Fatalf("Cannot create key.\n")
		}

		testAdminAdd("test@example.com", t)

		if resp := postService("newcenter?mail=test@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to create a notification center with invalid signature. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("notify?mail=test@example.com&center=test", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to send a notification with invalid signature. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("removecenter?mail=test@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to remove a notification center with invalid signature. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("test?mail=test@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to use the test service with invalid signature. Code: %d\n", resp.StatusCode)
		}
	})
}

func TestInvalidUser(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		stringpkey, _, err := genKeyPair(1024)
		if err != nil {
			t.Fatal(err)
		}
		key := stringToPrivateKey(stringpkey)
		if key == nil {
			t.Fatalf("Cannot create key.\n")
		}

		testAdminAdd("test2@example.com", t)

		if resp := postService("newcenter?mail=test@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to create a notification center with invalid signature. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("notify?mail=test@example.com&center=test", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to send a notification with invalid signature. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("removecenter?mail=test@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to remove a notification center with invalid signature. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("test?mail=test@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("It is possible to use the test service with invalid signature. Code: %d\n", resp.StatusCode)
		}
	})
}

func TestInvalidNotificationCenter(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		key := testAdminAdd("test@example.com", t)

		if resp := postService("removecenter?mail=test@example.com", "test", key, t); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Missing notification center don't send Not Found on deletion. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("notify?mail=test@example.com&center=test", "", key, t); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("Missing notification center don't send Not Found on notification. Code: %d\n", resp.StatusCode)
		}
	})
}

func TestHijackOtherUsersAccount(t *testing.T) {
	testWithServer(startBasicDummyServer, t, func(t *testing.T) {
		key := testAdminAdd("test@example.com", t)
		key2 := testAdminAdd("test2@example.com", t)

		if resp := postService("newcenter?mail=test2@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Attempting to create a notification center with invalid credentials does not return Unauthorized. Code: %d\n", resp.StatusCode)
		}

		postService("newcenter?mail=test2@example.com", "test", key2, t)

		if resp := postService("notify?mail=test2@example.com&center=test", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Attempting to send a notification with invalid credentials does not return Unauthorized. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("removecenter?mail=test2@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Attempting to delete a notification center with invalid credentials does not return Unauthorized. Code: %d\n", resp.StatusCode)
		}

		if resp := postService("test?mail=test2@example.com", "test", key, t); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Attempting to use the test service with invalid credentials does not return Unauthorized. Code: %d\n", resp.StatusCode)
		}
	})
}

func TestMySQLFunctional(t *testing.T) {
	config := getBaseConfig()

	if fileReachable("test/mysql.json") {
		mysqlconf, err := ReadConfig("test/mysql.json")
		if err == nil {
			config.DBName = mysqlconf.DBName
			config.DBUser = mysqlconf.DBUser
			config.DBPass = mysqlconf.DBPass
		} else {
			t.Log(err)
		}
	}

	if *dbuser != "" && *dbname != "" {
		config.DBName = *dbname
		config.DBUser = *dbuser
		config.DBPass = *dbpass
	}

	if config.DBName == "" || config.DBUser == "" {
		t.Logf("No MySQL user or database is given, skipping test.\n")
		return
	}

	backend := NewMySQLBackend(config)

	serverStarter := func(t *testing.T) *GoPushService {
		return startServer(config, backend, t)
	}

	testWithServer(serverStarter, t, func(t *testing.T) {
		fullFunctionalTest(t)
		_, err := backend.connection.Exec("DROP TABLE APIToken")
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestConfigReader(t *testing.T) {
	conf, err := ReadConfig("test/test.json")
	if err != nil {
		t.Fatal(err)
	}

	if conf.Address != ":8080" {
		t.Fatalf("Invalid Address in JSON.\n")
	}

	if conf.DBUser != "gopushu" {
		t.Fatalf("Invalid DBUser in JSON.\n")
	}

	if conf.DBPass != "gopushp" {
		t.Fatalf("Invalid DBPass in JSON.\n")
	}

	if conf.DBName != "gopushn" {
		t.Fatalf("Invalid DBName in JSON.\n")
	}

	if conf.CertFile != "c" {
		t.Fatalf("Invalid CertFile in JSON.\n")
	}

	if conf.KeyFile != "k" {
		t.Fatalf("Invalid KeyFile in JSON.\n")
	}

	if conf.AdminUser != "adminu" {
		t.Fatalf("Invalid AdminUser in JSON.\n")
	}

	if conf.AdminPass != "adminp" {
		t.Fatalf("Invalid AdminPass in JSON.\n")
	}

	if conf.Timeout != 60 {
		t.Fatalf("Invalid Timeout in JSON.\n")
	}

	if !conf.UserCache {
		t.Fatalf("Invalid UserCache in JSON.\n")
	}

	if conf.BroadcastBuffer != 4096 {
		t.Fatalf("Invalid BroadcastBuffer in JSON.\n")
	}

	if !conf.ExtraLogging {
		t.Fatalf("Invalid ExtraLogging in JSON.\n")
	}

	if conf.RedirectMainPage != "redir" {
		t.Fatalf("Invalid RedirectMainPage in JSON.\n")
	}
}

func fileReachable(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
