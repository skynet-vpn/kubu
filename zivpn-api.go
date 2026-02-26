package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ConfigFile = "/etc/zivpn/config.json"
	UserDB     = "/etc/zivpn/users.db"
	DomainFile = "/etc/zivpn/domain"
	ApiKeyFile = "/etc/zivpn/apikey"
	Port       = ":8080"
)

var AuthToken = "AutoFtBot-agskjgdvsbdreiWG1234512SDKrqw"

type Config struct {
	Listen string `json:"listen"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
	Obfs   string `json:"obfs"`
	Auth   struct {
		Mode   string   `json:"mode"`
		Config []string `json:"config"`
	} `json:"auth"`
}

type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Days     int    `json:"days"`
	Duration string `json:"duration"`
}

type LegacyCreateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Expired  int    `json:"expired"`
	Kuota    string `json:"kuota"`
	LimitIP  string `json:"limitip"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type LegacyMeta struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type LegacyResponse struct {
	Meta    LegacyMeta  `json:"meta"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

var mutex = &sync.Mutex{}

func main() {
	if keyBytes, err := ioutil.ReadFile(ApiKeyFile); err == nil {
		AuthToken = strings.TrimSpace(string(keyBytes))
	}

	http.HandleFunc("/api/user/create", authMiddleware(createUser))
	http.HandleFunc("/api/user/delete", authMiddleware(deleteUser))
	http.HandleFunc("/api/user/renew", authMiddleware(renewUser))
	http.HandleFunc("/api/users", authMiddleware(listUsers))
	http.HandleFunc("/api/info", authMiddleware(getSystemInfo))
	http.HandleFunc("/vps/sshvpn", authMiddlewareLegacy(createSSHAccount))
	http.HandleFunc("/vps/vmessall", authMiddlewareLegacy(createVMessAccount))
	http.HandleFunc("/vps/vlessall", authMiddlewareLegacy(createVLESSAccount))
	http.HandleFunc("/vps/trojanall", authMiddlewareLegacy(createTrojanAccount))
	http.HandleFunc("/createshadowsocks", authMiddlewareLegacy(createShadowsocksAccount))

	fmt.Printf("ZiVPN API berjalan di port %s\n", Port)
	log.Fatal(http.ListenAndServe(Port, nil))
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-API-Key")
		if token != AuthToken {
			jsonResponse(w, http.StatusUnauthorized, false, "Unauthorized", nil)
			return
		}
		next(w, r)
	}
}

func authMiddlewareLegacy(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.Header.Get("X-API-Key")
		}
		if token != AuthToken {
			legacyResponse(w, http.StatusUnauthorized, 401, "Unauthorized", nil)
			return
		}
		next(w, r)
	}
}

func jsonResponse(w http.ResponseWriter, status int, success bool, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Success: success,
		Message: message,
		Data:    data,
	})
}

func legacyResponse(w http.ResponseWriter, status int, code int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(LegacyResponse{
		Meta: LegacyMeta{
			Code:    code,
			Message: message,
		},
		Data:    data,
		Message: message,
	})
}

func createSSHAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		legacyResponse(w, http.StatusMethodNotAllowed, 405, "Method not allowed", nil)
		return
	}

	var req LegacyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		legacyResponse(w, http.StatusBadRequest, 400, "Invalid request body", nil)
		return
	}

	username := strings.TrimSpace(req.Username)
	password := strings.TrimSpace(req.Password)
	if username == "" {
		username = password
	}
	if username == "" || req.Expired <= 0 {
		legacyResponse(w, http.StatusBadRequest, 400, "username dan expired harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membaca config", nil)
		return
	}

	for _, p := range config.Auth.Config {
		if p == username {
			legacyResponse(w, http.StatusConflict, 409, "User sudah ada", nil)
			return
		}
	}

	config.Auth.Config = append(config.Auth.Config, username)
	if err := saveConfig(config); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menyimpan config", nil)
		return
	}

	expiry := time.Now().Add(time.Duration(req.Expired) * 24 * time.Hour)
	expDate := expiry.Format("2006-01-02")
	expTime := expiry.Format("15:04:05")
	entry := fmt.Sprintf("%s | %s\n", username, expDate)

	f, err := os.OpenFile(UserDB, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membuka database user", nil)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menulis database user", nil)
		return
	}

	if err := restartService(); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal merestart service", nil)
		return
	}

	hostname := getDomainValue()
	if hostname == "Tidak diatur" {
		if ip := getPublicIP(); ip != "" {
			hostname = ip
		}
	}

	data := map[string]interface{}{
		"hostname": hostname,
		"ISP":      "Unknown",
		"CITY":     "Unknown",
		"username": username,
		"password": password,
		"pubkey":   "-",
		"exp":      expDate,
		"time":     expTime,
		"port": map[string]string{
			"tls":       "443",
			"none":      "80",
			"ovpntcp":   "1194",
			"ovpnudp":   "2200",
			"sshohp":    "3128",
			"udpcustom": "1-65535",
		},
	}

	legacyResponse(w, http.StatusOK, 200, "OK", data)
}

func createVMessAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		legacyResponse(w, http.StatusMethodNotAllowed, 405, "Method not allowed", nil)
		return
	}

	var req LegacyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		legacyResponse(w, http.StatusBadRequest, 400, "Invalid request body", nil)
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" || req.Expired <= 0 {
		legacyResponse(w, http.StatusBadRequest, 400, "username dan expired harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membaca config", nil)
		return
	}

	for _, p := range config.Auth.Config {
		if p == username {
			legacyResponse(w, http.StatusConflict, 409, "User sudah ada", nil)
			return
		}
	}

	config.Auth.Config = append(config.Auth.Config, username)
	if err := saveConfig(config); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menyimpan config", nil)
		return
	}

	expiry := time.Now().Add(time.Duration(req.Expired) * 24 * time.Hour)
	expDate := expiry.Format("2006-01-02")
	entry := fmt.Sprintf("%s | %s\n", username, expDate)

	f, err := os.OpenFile(UserDB, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membuka database user", nil)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menulis database user", nil)
		return
	}

	if err := restartService(); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal merestart service", nil)
		return
	}

	hostname := getDomainValue()
	if hostname == "Tidak diatur" {
		if ip := getPublicIP(); ip != "" {
			hostname = ip
		}
	}

	generateUUID := "550e8400-e29b-41d4-a716-446655440000"

	data := map[string]interface{}{
		"hostname": hostname,
		"ISP":      "Unknown",
		"CITY":     "Unknown",
		"username": username,
		"uuid":     generateUUID,
		"expired":  expDate,
		"time":     expiry.Format("15:04:05"),
		"port": map[string]string{
			"tls":  "443",
			"none": "80",
			"any":  "1-65535",
		},
		"path": map[string]string{
			"stn":   "/vmess",
			"multi": "/vmess-multi",
			"grpc":  "vmess-grpc",
			"up":    "/upgrade",
		},
		"link": map[string]string{
			"tls":    "vmess://link-tls",
			"none":   "vmess://link-none",
			"grpc":   "vmess://link-grpc",
			"uptls":  "vmess://link-uptls",
			"upntls": "vmess://link-upntls",
		},
	}

	legacyResponse(w, http.StatusOK, 200, "OK", data)
}

func createVLESSAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		legacyResponse(w, http.StatusMethodNotAllowed, 405, "Method not allowed", nil)
		return
	}

	var req LegacyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		legacyResponse(w, http.StatusBadRequest, 400, "Invalid request body", nil)
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" || req.Expired <= 0 {
		legacyResponse(w, http.StatusBadRequest, 400, "username dan expired harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membaca config", nil)
		return
	}

	for _, p := range config.Auth.Config {
		if p == username {
			legacyResponse(w, http.StatusConflict, 409, "User sudah ada", nil)
			return
		}
	}

	config.Auth.Config = append(config.Auth.Config, username)
	if err := saveConfig(config); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menyimpan config", nil)
		return
	}

	expiry := time.Now().Add(time.Duration(req.Expired) * 24 * time.Hour)
	expDate := expiry.Format("2006-01-02")
	entry := fmt.Sprintf("%s | %s\n", username, expDate)

	f, err := os.OpenFile(UserDB, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membuka database user", nil)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menulis database user", nil)
		return
	}

	if err := restartService(); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal merestart service", nil)
		return
	}

	hostname := getDomainValue()
	if hostname == "Tidak diatur" {
		if ip := getPublicIP(); ip != "" {
			hostname = ip
		}
	}

	generateUUID := "550e8400-e29b-41d4-a716-446655440001"

	data := map[string]interface{}{
		"hostname": hostname,
		"ISP":      "Unknown",
		"CITY":     "Unknown",
		"username": username,
		"uuid":     generateUUID,
		"expired":  expDate,
		"time":     expiry.Format("15:04:05"),
		"port": map[string]string{
			"tls":  "443",
			"none": "80",
			"any":  "1-65535",
		},
		"path": map[string]string{
			"stn":   "/vless",
			"multi": "/vless-multi",
			"grpc":  "vless-grpc",
			"up":    "/upgrade",
		},
		"link": map[string]string{
			"tls":    "vless://link-tls",
			"none":   "vless://link-none",
			"grpc":   "vless://link-grpc",
			"uptls":  "vless://link-uptls",
			"upntls": "vless://link-upntls",
		},
	}

	legacyResponse(w, http.StatusOK, 200, "OK", data)
}

func createTrojanAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		legacyResponse(w, http.StatusMethodNotAllowed, 405, "Method not allowed", nil)
		return
	}

	var req LegacyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		legacyResponse(w, http.StatusBadRequest, 400, "Invalid request body", nil)
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" || req.Expired <= 0 {
		legacyResponse(w, http.StatusBadRequest, 400, "username dan expired harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membaca config", nil)
		return
	}

	for _, p := range config.Auth.Config {
		if p == username {
			legacyResponse(w, http.StatusConflict, 409, "User sudah ada", nil)
			return
		}
	}

	config.Auth.Config = append(config.Auth.Config, username)
	if err := saveConfig(config); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menyimpan config", nil)
		return
	}

	expiry := time.Now().Add(time.Duration(req.Expired) * 24 * time.Hour)
	expDate := expiry.Format("2006-01-02")
	entry := fmt.Sprintf("%s | %s\n", username, expDate)

	f, err := os.OpenFile(UserDB, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membuka database user", nil)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menulis database user", nil)
		return
	}

	if err := restartService(); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal merestart service", nil)
		return
	}

	hostname := getDomainValue()
	if hostname == "Tidak diatur" {
		if ip := getPublicIP(); ip != "" {
			hostname = ip
		}
	}

	generateUUID := "550e8400-e29b-41d4-a716-446655440002"

	data := map[string]interface{}{
		"hostname": hostname,
		"ISP":      "Unknown",
		"CITY":     "Unknown",
		"username": username,
		"uuid":     generateUUID,
		"expired":  expDate,
		"time":     expiry.Format("15:04:05"),
		"port": map[string]string{
			"tls":  "443",
			"none": "80",
			"any":  "1-65535",
		},
		"path": map[string]string{
			"stn":   "/trojan",
			"multi": "/trojan-multi",
			"grpc":  "trojan-grpc",
			"up":    "/upgrade",
		},
		"link": map[string]string{
			"tls":   "trojan://link-tls",
			"grpc":  "trojan://link-grpc",
			"uptls": "trojan://link-uptls",
		},
	}

	legacyResponse(w, http.StatusOK, 200, "OK", data)
}

func createShadowsocksAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		legacyResponse(w, http.StatusMethodNotAllowed, 405, "Method not allowed", nil)
		return
	}

	username := r.URL.Query().Get("user")
	expStr := r.URL.Query().Get("exp")
	quota := r.URL.Query().Get("quota")
	iplimit := r.URL.Query().Get("iplimit")

	if username == "" || expStr == "" {
		legacyResponse(w, http.StatusBadRequest, 400, "user dan exp harus valid", nil)
		return
	}

	if quota == "" {
		quota = "0"
	}
	if iplimit == "" {
		iplimit = "0"
	}

	exp, err := strconv.Atoi(expStr)
	if err != nil || exp <= 0 {
		legacyResponse(w, http.StatusBadRequest, 400, "exp harus berupa bilangan positif", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membaca config", nil)
		return
	}

	for _, p := range config.Auth.Config {
		if p == username {
			legacyResponse(w, http.StatusConflict, 409, "User sudah ada", nil)
			return
		}
	}

	config.Auth.Config = append(config.Auth.Config, username)
	if err := saveConfig(config); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menyimpan config", nil)
		return
	}

	expiry := time.Now().Add(time.Duration(exp) * 24 * time.Hour)
	expDate := expiry.Format("2006-01-02")
	entry := fmt.Sprintf("%s | %s\n", username, expDate)

	f, err := os.OpenFile(UserDB, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal membuka database user", nil)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal menulis database user", nil)
		return
	}

	if err := restartService(); err != nil {
		legacyResponse(w, http.StatusInternalServerError, 500, "Gagal merestart service", nil)
		return
	}

	hostname := getDomainValue()
	if hostname == "Tidak diatur" {
		if ip := getPublicIP(); ip != "" {
			hostname = ip
		}
	}

	quotaDisplay := "0 GB"
	if quota != "0" {
		quotaDisplay = quota + " GB"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"username":     username,
			"domain":       hostname,
			"ns_domain":    "ns-" + hostname,
			"pubkey":       "-",
			"expired":      expDate,
			"quota":        quotaDisplay,
			"ip_limit":     iplimit,
			"ss_link_ws":   "ss://link-ws",
			"ss_link_grpc": "ss://link-grpc",
		},
	})
}

func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	accountID := strings.TrimSpace(req.Username)
	if accountID == "" {
		accountID = strings.TrimSpace(req.Password)
	}
	if accountID == "" || (req.Days <= 0 && strings.TrimSpace(req.Duration) == "") {
		jsonResponse(w, http.StatusBadRequest, false, "Username/password dan days/duration harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca config", nil)
		return
	}

	for _, p := range config.Auth.Config {
		if p == accountID {
			jsonResponse(w, http.StatusConflict, false, "User sudah ada", nil)
			return
		}
	}

	config.Auth.Config = append(config.Auth.Config, accountID)
	if err := saveConfig(config); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan config", nil)
		return
	}

	// Calculate expiry time based on either Duration (preferred) or Days
	var expiry time.Time
	durStr := strings.TrimSpace(req.Duration)
	if durStr != "" {
		// Support "Nd" for days and standard Go duration strings like "1h"
		if strings.HasSuffix(durStr, "d") {
			n, err := strconv.Atoi(strings.TrimSuffix(durStr, "d"))
			if err != nil {
				jsonResponse(w, http.StatusBadRequest, false, "Format duration tidak valid", nil)
				return
			}
			expiry = time.Now().Add(time.Duration(n*24) * time.Hour)
		} else {
			parsed, err := time.ParseDuration(durStr)
			if err != nil {
				jsonResponse(w, http.StatusBadRequest, false, "Format duration tidak valid", nil)
				return
			}
			expiry = time.Now().Add(parsed)
		}
	} else {
		expiry = time.Now().Add(time.Duration(req.Days) * 24 * time.Hour)
	}

	// Choose format: if duration provided in hours (not full days) include time component
	var expDate string
	if durStr != "" && !strings.HasSuffix(durStr, "d") {
		expDate = expiry.Format("2006-01-02 15:04:05")
	} else {
		expDate = expiry.Format("2006-01-02")
	}
	entry := fmt.Sprintf("%s | %s\n", accountID, expDate)

	f, err := os.OpenFile(UserDB, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membuka database user", nil)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menulis database user", nil)
		return
	}

	if err := restartService(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
		return
	}

	domain := "Tidak diatur"
	if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
		domain = strings.TrimSpace(string(domainBytes))
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil dibuat", map[string]string{
		"username": accountID,
		"password": accountID,
		"expired":  expDate,
		"domain":   domain,
	})
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	accountID := strings.TrimSpace(req.Username)
	if accountID == "" {
		accountID = strings.TrimSpace(req.Password)
	}
	if accountID == "" {
		jsonResponse(w, http.StatusBadRequest, false, "Username/password harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca config", nil)
		return
	}

	found := false
	newConfigAuth := []string{}
	for _, p := range config.Auth.Config {
		if p == accountID {
			found = true
		} else {
			newConfigAuth = append(newConfigAuth, p)
		}
	}

	if !found {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan", nil)
		return
	}

	config.Auth.Config = newConfigAuth
	if err := saveConfig(config); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan config", nil)
		return
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	newUsers := []string{}
	for _, line := range users {
		parts := strings.Split(line, "|")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) == accountID {
			continue
		}
		newUsers = append(newUsers, line)
	}

	if err := saveUsers(newUsers); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	if err := restartService(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil dihapus", nil)
}

func renewUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	accountID := strings.TrimSpace(req.Username)
	if accountID == "" {
		accountID = strings.TrimSpace(req.Password)
	}
	if accountID == "" {
		jsonResponse(w, http.StatusBadRequest, false, "Username/password harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	found := false
	newUsers := []string{}
	var newExpDate string

	for _, line := range users {
		parts := strings.Split(line, "|")
		if len(parts) >= 2 && strings.TrimSpace(parts[0]) == accountID {
			found = true
			currentExpStr := strings.TrimSpace(parts[1])
			currentExp, err := time.Parse("2006-01-02", currentExpStr)
			if err != nil {
				// Jika format tanggal salah, anggap hari ini
				currentExp = time.Now()
			}

			// Jika sudah expired, mulai dari hari ini. Jika belum, tambah dari tanggal expired.
			if currentExp.Before(time.Now()) {
				currentExp = time.Now()
			}

			// determine extension duration: prefer Duration if provided
			durStr := strings.TrimSpace(req.Duration)
			var addDur time.Duration
			if durStr != "" {
				if strings.HasSuffix(durStr, "d") {
					n, err := strconv.Atoi(strings.TrimSuffix(durStr, "d"))
					if err != nil {
						jsonResponse(w, http.StatusBadRequest, false, "Format duration tidak valid", nil)
						return
					}
					addDur = time.Duration(n*24) * time.Hour
				} else {
					parsed, err := time.ParseDuration(durStr)
					if err != nil {
						jsonResponse(w, http.StatusBadRequest, false, "Format duration tidak valid", nil)
						return
					}
					addDur = parsed
				}
			} else {
				addDur = time.Duration(req.Days) * 24 * time.Hour
			}

			newExp := currentExp.Add(addDur)
			// if Duration was provided as hours, store full timestamp, otherwise store date only
			if durStr != "" && !strings.HasSuffix(durStr, "d") {
				newExpDate = newExp.Format("2006-01-02 15:04:05")
			} else {
				newExpDate = newExp.Format("2006-01-02")
			}
			newUsers = append(newUsers, fmt.Sprintf("%s | %s", accountID, newExpDate))
		} else {
			newUsers = append(newUsers, line)
		}
	}

	if !found {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan di database", nil)
		return
	}

	if err := saveUsers(newUsers); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	// Restart service mungkin tidak diperlukan untuk renew, tapi bagus untuk memastikan konsistensi
	if err := restartService(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil diperpanjang", map[string]string{
		"username": accountID,
		"password": accountID,
		"expired":  newExpDate,
	})
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	type UserInfo struct {
		Password string `json:"password"`
		Expired  string `json:"expired"`
		Status   string `json:"status"`
	}

	userList := []UserInfo{}
	today := time.Now().Format("2006-01-02")

	for _, line := range users {
		parts := strings.Split(line, "|")
		if len(parts) >= 2 {
			pass := strings.TrimSpace(parts[0])
			exp := strings.TrimSpace(parts[1])
			status := "Active"
			if exp < today {
				status = "Expired"
			}
			userList = append(userList, UserInfo{
				Password: pass,
				Expired:  exp,
				Status:   status,
			})
		}
	}

	jsonResponse(w, http.StatusOK, true, "Daftar user", userList)
}

func getSystemInfo(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("curl", "-s", "ifconfig.me")
	ipPub, _ := cmd.Output()

	cmd = exec.Command("hostname", "-I")
	ipPriv, _ := cmd.Output()

	domain := "Tidak diatur"
	if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
		domain = strings.TrimSpace(string(domainBytes))
	}

	info := map[string]string{
		"domain":     domain,
		"public_ip":  strings.TrimSpace(string(ipPub)),
		"private_ip": strings.Fields(string(ipPriv))[0],
		"port":       "5667",
		"service":    "zivpn",
	}

	jsonResponse(w, http.StatusOK, true, "System Info", info)
}

// --- Helper Functions ---

func loadConfig() (Config, error) {
	var config Config
	file, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(file, &config)
	return config, err
}

func saveConfig(config Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(ConfigFile, data, 0644)
}

func loadUsers() ([]string, error) {
	file, err := ioutil.ReadFile(UserDB)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(file), "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func saveUsers(lines []string) error {
	data := strings.Join(lines, "\n") + "\n"
	return ioutil.WriteFile(UserDB, []byte(data), 0644)
}

func restartService() error {
	cmd := exec.Command("systemctl", "restart", "zivpn.service")
	return cmd.Run()
}

func getDomainValue() string {
	domain := "Tidak diatur"
	if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
		domain = strings.TrimSpace(string(domainBytes))
	}
	return domain
}

func getPublicIP() string {
	cmd := exec.Command("curl", "-s", "ifconfig.me")
	ipPub, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ipPub))
}
