package gopush

import "testing"

import (
	"fmt"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var port = 18080
const adminUser = "admin"
const adminPass = "admin"

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
	svc := NewService(config, NewDummyBackend())
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

func getBaseConfig() Config {
	return Config{
		Address: fmt.Sprintf(":%d", port),
		AdminUser: adminUser,
		AdminPass: adminPass,
		Timeout: 0,
		UserCache: true,
		BroadcastBuffer: 4096,
		ExtraLogging: false,
		RedirectMainPage: "",
	}
}

func getPath(path string) string {
	return fmt.Sprintf("http://localhost:%d/%s", port, path)
}

func getBody(resp *http.Response) string {
	respbody, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	return string(respbody)
}

func getAdmin(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", getPath(path), nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(adminUser, adminPass)

	return http.DefaultClient.Do(req)
}

func postAdmin(path string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", getPath(path), strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(adminUser, adminPass)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return http.DefaultClient.Do(req)
}

func postService(path string, body string, key *rsa.PrivateKey) (*http.Response, error) {
	req, err := http.NewRequest("POST", getPath(path), strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	signature := sign(body, key)
	req.Header.Set("Authorization", "GoPush " + signature)

	return http.DefaultClient.Do(req)
}

func getAdminMainPage(t *testing.T) adminPageData {
	resp, err := getAdmin("admin")
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Invalid response returned from /admin, status code: %d\n", resp.StatusCode)
	}

	body := getBody(resp)

	var page adminPageData
	err = json.Unmarshal([]byte(body), &page)
	if err != nil {
		t.Fatal(err)
	}

	return page
}

func testAdminAdd(mail string, t *testing.T) *rsa.PrivateKey {
	page := getAdminMainPage(t)

	resp, err := postAdmin("admin/add", fmt.Sprintf("mail=test@example.com&publickey=&nonce=%s&formid=%s", page.Nonce, page.FormID))
	if err != nil {
		t.Fatal(err)
	}

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

	resp, err := postAdmin("admin/remove", fmt.Sprintf("mail=test@example.com&nonce=%s&formid=%s", page.Nonce, page.FormID))
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusFound { // The delete page redirects.
		t.Fatalf("Failed to remove account, code: %d\n", resp.StatusCode)
	}
}

func testAdminListEmpty(t *testing.T) {
	page := getAdminMainPage(t)
	if len(page.APITokens) > 1 { // An empty item is there at the end because of a JSON serialization hack.
		t.Fatalf("The account list is not empty. Number of items: %d\n", len(page.APITokens) - 1)
	}
}

func testNotificationCenterCreation(key *rsa.PrivateKey, t *testing.T) {
	resp, err := postService("newcenter?mail=test@example.com", "test", key)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create notification center, code: %d\n", resp.StatusCode)
	}
}

func testNotificationWithPing(key *rsa.PrivateKey, t *testing.T, shouldSucceed bool) {
	testmsg := genRandomHash(128)
	resp, err := postService("notify?mail=test@example.com&center=test", testmsg, key)
	if err != nil {
		t.Fatal(err)
	}

	if shouldSucceed {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to send a notification, code: %d\n", resp.StatusCode)
		}
	} else {
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("Successfully sent notification.\n")
		}
		return
	}

	resp, err = http.DefaultClient.Get(getPath("ping?center=" + getCenterName("test@example.com", "test")))
	if err != nil {
		t.Fatal(err)
	}

	if shouldSucceed {
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Failed to ping, code: %d\n", resp.StatusCode)
		}
	} else {
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("Ping succeeded.\n")
		}
	}

	body := getBody(resp)
	if body != testmsg {
		t.Fatalf("Message retrieval through ping is failed. Expected: '%s', got: '%s'\n", testmsg, body)
	}
}

func testNotificationCenterRemoval(key *rsa.PrivateKey, t *testing.T) {
	resp, err := postService("removecenter?mail=test@example.com", "test", key)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to remove notification center, code: %d\n", resp.StatusCode)
	}

	resp, err = http.DefaultClient.Get(getPath("ping?center=" + getCenterName("test@example.com", "test")))
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
	testNotificationCenterCreation(key, t)
	testNotificationWithPing(key, t, true)
	testNotificationCenterRemoval(key, t)
	testAdminRemove(t)
	testAdminListEmpty(t)
}

func TestBasicFunctional(t *testing.T) {
	svc := startBasicDummyServer(t)
	if svc == nil {
		t.Fatal(svc)
	}
	defer func() {
		svc.Stop()
		port++
	}()
	<-time.After(2 * time.Second)
	
	fullFunctionalTest(t)
}

func TestTimeoutFunctional(t *testing.T) {
	svc := startTimeoutDummyServer(t)
	if svc == nil {
		t.Fatal(svc)
	}
	defer func() {
		svc.Stop()
		port++
	}()
	<-time.After(2 * time.Second)

	key := testAdminAdd("test@example.com", t)
	if key == nil {
		t.Fatal("Invalid key")
	}

	testNotificationCenterCreation(key, t)
	<-time.After(2 * time.Second)
	testNotificationWithPing(key, t, false)
}
