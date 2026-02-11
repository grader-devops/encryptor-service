package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Конфигурация из переменных окружения
type Config struct {
	PublicKeyPath  string
	PrivateKeyPath string
	Port           string
	EnableDecrypt  bool
	APIKeyHash     string // SHA256 хэш API ключа для авторизации
	AuthEnabled    bool   // Включена ли авторизация
}

type PageData struct {
	Title          string
	EncryptedText  string
	DecryptedText  string
	OriginalText   string
	Error          string
	Success        string
	PublicKeyInfo  string
	PrivateKeyInfo string
	ExampleUsage   string
	APIEndpoint    string
	Port           string
	EnableDecrypt  bool
	AuthEnabled    bool
}

var (
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	config     Config
	keyMutex   sync.RWMutex
)

func init() {
	// Загружаем конфигурацию
	config = Config{
		PublicKeyPath:  getEnv("RSA_PUBLIC_KEY_PATH", "./public.pem"),
		PrivateKeyPath: getEnv("RSA_PRIVATE_KEY_PATH", "./private.pem"),
		Port:           getEnv("PORT", "8080"),
		EnableDecrypt:  getEnvBool("ENABLE_DECRYPT", true),
		AuthEnabled:    getEnvBool("AUTH_ENABLED", true), // По умолчанию включена
		APIKeyHash:     getEnv("API_KEY_HASH", ""),       // SHA256 хэш API ключа
	}

	// Если авторизация включена, но хэш не указан - предупреждение
	if config.AuthEnabled && config.APIKeyHash == "" {
		log.Printf("⚠️  Предупреждение: авторизация включена, но API_KEY_HASH не указан")
		log.Printf("ℹ️  Установите переменную API_KEY_HASH или отключите авторизацию")
	}

	// Загружаем публичный ключ
	if _, err := os.Stat(config.PublicKeyPath); err == nil {
		if err := loadPublicKey(); err != nil {
			log.Printf("⚠️  Предупреждение: не удалось загрузить публичный ключ: %v", err)
		}
	}

	// Загружаем приватный ключ если указан и включена расшифровка
	if config.EnableDecrypt && config.PrivateKeyPath != "" {
		if err := loadPrivateKey(); err != nil {
			log.Printf("⚠️  Предупреждение: не удалось загрузить приватный ключ: %v", err)
			log.Printf("ℹ️  Автоматическая расшифровка будет отключена")
			config.EnableDecrypt = false
		} else {
			log.Println("✅ Приватный ключ успешно загружен")
		}
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		return strings.ToLower(value) == "true" || value == "1"
	}
	return defaultValue
}

func loadPublicKey() error {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	// Читаем публичный ключ из файла
	keyData, err := os.ReadFile(config.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать файл ключа: %v", err)
	}

	// Декодируем PEM формат
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("неверный формат PEM")
	}

	// Парсим публичный ключ
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("не удалось распарсить публичный ключ: %v", err)
	}

	var ok bool
	publicKey, ok = pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("ключ не является RSA публичным ключом")
	}

	log.Printf("✅ Публичный ключ успешно загружен (%d бит)", publicKey.Size()*8)
	return nil
}

func loadPrivateKey() error {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	// Читаем приватный ключ
	var keyData []byte
	var err error

	// Проверяем, может быть ключ задан прямо в переменной окружения
	if strings.HasPrefix(config.PrivateKeyPath, "env://") {
		envName := strings.TrimPrefix(config.PrivateKeyPath, "env://")
		keyData = []byte(getEnv(envName, ""))
		if len(keyData) == 0 {
			return fmt.Errorf("переменная окружения %s пуста", envName)
		}
	} else {
		// Читаем из файла
		keyData, err = os.ReadFile(config.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("не удалось прочитать файл ключа: %v", err)
		}
	}

	// Декодируем PEM формат
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("неверный формат PEM")
	}

	// Парсим приватный ключ
	var privKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 формат
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("ошибка парсинга PKCS#1 ключа: %v", err)
		}
		
	case "PRIVATE KEY":
		// PKCS#8 формат
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("ошибка парсинга PKCS#8 ключа: %v", err)
		}
		
		var ok bool
		privKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("ключ не является RSA приватным ключом")
		}
		
	case "ENCRYPTED PRIVATE KEY":
		return fmt.Errorf("зашифрованные ключи не поддерживаются")
		
	default:
		return fmt.Errorf("неподдерживаемый тип ключа: %s", block.Type)
	}
	
	// Проверяем валидность ключа
	if err := privKey.Validate(); err != nil {
		return fmt.Errorf("невалидный приватный ключ: %v", err)
	}

	privateKey = privKey
	log.Printf("✅ Приватный ключ успешно загружен (%d бит)", privateKey.Size()*8)
	
	// Проверяем соответствие публичного и приватного ключей
	if publicKey != nil {
		// Извлекаем публичный ключ из приватного
		derivedPublicKey := &privateKey.PublicKey
		
		// Сравниваем модули (грубая проверка)
		if publicKey.N.Cmp(derivedPublicKey.N) != 0 {
			log.Printf("⚠️  Предупреждение: публичный и приватный ключи могут не соответствовать друг другу")
		} else {
			log.Println("✅ Публичный и приватный ключи соответствуют друг другу")
		}
	}
	
	return nil
}

// Мониторинг изменений файлов ключей
func watchKeyFiles() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		// Проверяем публичный ключ
		if _, err := os.Stat(config.PublicKeyPath); err == nil {
			if err := loadPublicKey(); err != nil {
				log.Printf("❌ Ошибка перезагрузки публичного ключа: %v", err)
			}
		}
		
		// Проверяем приватный ключ
		if config.EnableDecrypt && config.PrivateKeyPath != "" && !strings.HasPrefix(config.PrivateKeyPath, "env://") {
			if _, err := os.Stat(config.PrivateKeyPath); err == nil {
				if err := loadPrivateKey(); err != nil {
					log.Printf("❌ Ошибка перезагрузки приватного ключа: %v", err)
				}
			}
		}
	}
}

// EncryptText шифрует текст с помощью публичного ключа
func EncryptText(text string) (string, error) {
	keyMutex.RLock()
	defer keyMutex.RUnlock()
	
	if publicKey == nil {
		return "", fmt.Errorf("публичный ключ не загружен")
	}

	// Разбиваем текст на блоки для шифрования
	blockSize := publicKey.Size() - 2*sha256.New().Size() - 2
	bytes := []byte(text)
	var encryptedBytes []byte

	for i := 0; i < len(bytes); i += blockSize {
		end := i + blockSize
		if end > len(bytes) {
			end = len(bytes)
		}

		block := bytes[i:end]
		
		// Шифрование с использованием OAEP
		encryptedBlock, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			publicKey,
			block,
			nil,
		)
		
		if err != nil {
			return "", fmt.Errorf("ошибка шифрования блока: %v", err)
		}
		encryptedBytes = append(encryptedBytes, encryptedBlock...)
	}

	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// DecryptText расшифровывает текст с помощью загруженного приватного ключа
func DecryptText(encryptedText string) (string, error) {
	keyMutex.RLock()
	defer keyMutex.RUnlock()
	
	if privateKey == nil {
		return "", fmt.Errorf("приватный ключ не загружен")
	}

	// Декодируем base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", fmt.Errorf("неверный формат base64: %v", err)
	}

	// Разбиваем на блоки для дешифрования
	blockSize := privateKey.Size()
	var decryptedBytes []byte

	for i := 0; i < len(encryptedBytes); i += blockSize {
		end := i + blockSize
		if end > len(encryptedBytes) {
			end = len(encryptedBytes)
		}

		block := encryptedBytes[i:end]
		
		// Дешифрование
		decryptedBlock, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			privateKey,
			block,
			nil,
		)
		
		if err != nil {
			return "", fmt.Errorf("ошибка дешифрования блока: %v", err)
		}
		decryptedBytes = append(decryptedBytes, decryptedBlock...)
	}

	return string(decryptedBytes), nil
}

// DecryptTextWithKey расшифровывает текст с переданным приватным ключом (для API)
func DecryptTextWithKey(encryptedText string, privateKeyPEM string) (string, error) {
	// Декодируем PEM формат
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("неверный формат PEM")
	}

	// Парсим приватный ключ
	var privKey *rsa.PrivateKey
	var err error
	
	switch block.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			err = parseErr
		} else {
			var ok bool
			privKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				err = fmt.Errorf("ключ не является RSA приватным ключом")
			}
		}
	default:
		err = fmt.Errorf("неподдерживаемый тип ключа: %s", block.Type)
	}
	
	if err != nil {
		return "", fmt.Errorf("ошибка загрузки приватного ключа: %v", err)
	}
	
	if err := privKey.Validate(); err != nil {
		return "", fmt.Errorf("невалидный приватный ключ: %v", err)
	}

	// Декодируем base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", fmt.Errorf("неверный формат base64: %v", err)
	}

	// Разбиваем на блоки для дешифрования
	blockSize := privKey.Size()
	var decryptedBytes []byte

	for i := 0; i < len(encryptedBytes); i += blockSize {
		end := i + blockSize
		if end > len(encryptedBytes) {
			end = len(encryptedBytes)
		}

		block := encryptedBytes[i:end]
		
		// Дешифрование
		decryptedBlock, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			privKey,
			block,
			nil,
		)
		
		if err != nil {
			return "", fmt.Errorf("ошибка дешифрования блока: %v", err)
		}
		decryptedBytes = append(decryptedBytes, decryptedBlock...)
	}

	return string(decryptedBytes), nil
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Генерируем пример использования
	var exampleEncrypted string
	if publicKey != nil {
		exampleText := "Hello, World!"
		encrypted, err := EncryptText(exampleText)
		if err != nil {
			exampleEncrypted = "Ошибка генерации примера: " + err.Error()
		} else {
			exampleEncrypted = encrypted
		}
	} else {
		exampleEncrypted = "Публичный ключ не загружен"
	}
	
	// Генерируем пример API запроса
	apiExample := fmt.Sprintf("curl -X POST http://localhost:%s/encrypt \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"text\": \"%s\"}'", 
		config.Port, "Your secret text")

	data := PageData{
		Title:         "RSA Шифрователь",
		PublicKeyInfo: getPublicKeyInfo(),
		PrivateKeyInfo: getPrivateKeyInfo(),
		ExampleUsage:  exampleEncrypted,
		APIEndpoint:   apiExample,
		Port:          config.Port,
		EnableDecrypt: config.EnableDecrypt,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getPublicKeyInfo() string {
	keyMutex.RLock()
	defer keyMutex.RUnlock()
	
	if publicKey == nil {
		return "Публичный ключ не загружен"
	}
	return fmt.Sprintf("Загружен (%d бит)", publicKey.Size()*8)
}

func getPrivateKeyInfo() string {
	keyMutex.RLock()
	defer keyMutex.RUnlock()
	
	if !config.EnableDecrypt {
		return "Автоматическая расшифровка отключена"
	}
	
	if privateKey == nil {
		return "Приватный ключ не загружен"
	}
	return fmt.Sprintf("Загружен (%d бит) - автоматическая расшифровка включена", privateKey.Size()*8)
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Поддерживаем оба формата: form-data и JSON
	var text string
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		// Обработка JSON запроса
		var request struct {
			Text string `json:"text"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, `{"error": "Неверный JSON формат"}`, http.StatusBadRequest)
			return
		}
		text = request.Text
		
		// Шифруем текст
		encrypted, err := EncryptText(text)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		
		// Возвращаем JSON ответ
		response := map[string]string{
			"encrypted":     encrypted,
			"original":      text,
			"format":        "base64",
			"algorithm":     "RSA-OAEP-SHA256",
			"key_size_bits": fmt.Sprintf("%d", publicKey.Size()*8),
			"decrypt_available": fmt.Sprintf("%v", config.EnableDecrypt),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	} else {
		// Обработка формы
		text = strings.TrimSpace(r.FormValue("text"))
		
		tmpl, err := template.ParseFiles("templates/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := PageData{
			Title:        "Результат шифрования",
			Port:         config.Port,
			EnableDecrypt: config.EnableDecrypt,
		}

		if text == "" {
			data.Error = "Введите текст для шифрования"
		} else {
			encrypted, err := EncryptText(text)
			if err != nil {
				data.Error = "Ошибка шифрования: " + err.Error()
			} else {
				data.EncryptedText = encrypted
				data.OriginalText = text
				data.Success = "Текст успешно зашифрован!"
			}
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Метод не поддерживается"}`, http.StatusMethodNotAllowed)
		return
	}

	// Поддерживаем JSON
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		http.Error(w, `{"error": "Требуется Content-Type: application/json"}`, http.StatusBadRequest)
		return
	}

	// Обработка JSON запроса
	var request struct {
		EncryptedText  string `json:"encrypted_text"`
		PrivateKeyPEM  string `json:"private_key,omitempty"` // Опционально
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, `{"error": "Неверный JSON формат"}`, http.StatusBadRequest)
		return
	}
	
	// Валидация входных данных
	if request.EncryptedText == "" {
		http.Error(w, `{"error": "Поле 'encrypted_text' обязательно"}`, http.StatusBadRequest)
		return
	}
	
	var decrypted string
	var err error
	var keySource string
	
	// Определяем источник ключа для дешифрования
	if request.PrivateKeyPEM != "" {
		// Используем переданный ключ
		decrypted, err = DecryptTextWithKey(request.EncryptedText, request.PrivateKeyPEM)
		keySource = "предоставленный"
	} else if config.EnableDecrypt && privateKey != nil {
		// Используем загруженный ключ
		decrypted, err = DecryptText(request.EncryptedText)
		keySource = "системный"
	} else {
		http.Error(w, `{"error": "Приватный ключ не предоставлен и автоматическая расшифровка отключена"}`, http.StatusBadRequest)
		return
	}
	
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Ошибка дешифрования: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	
	// Аудит запроса (логируем факт дешифрования без самого текста)
	log.Printf("🔓 Дешифрование выполнено. Источник ключа: %s, длина зашифрованного текста: %d", 
		keySource, len(request.EncryptedText))
	
	// Возвращаем JSON ответ
	response := map[string]string{
		"decrypted":       decrypted,
		"key_source":      keySource,
		"status":          "success",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	keyMutex.RLock()
	defer keyMutex.RUnlock()
	
	status := map[string]interface{}{
		"status":               "ok",
		"service":              "rsa-encryptor-decryptor",
		"public_key_loaded":    publicKey != nil,
		"private_key_loaded":   privateKey != nil,
		"auto_decrypt_enabled": config.EnableDecrypt,
		"endpoints":            []string{"/encrypt", "/decrypt", "/auto-decrypt", "/health"},
		"version":              "2.0.0",
	}
	
	if publicKey != nil {
		status["public_key_size_bits"] = publicKey.Size() * 8
	}
	
	if privateKey != nil {
		status["private_key_size_bits"] = privateKey.Size() * 8
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
// Middleware для авторизации
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Если авторизация отключена - пропускаем
		if !config.AuthEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// Проверяем API ключ
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.Header.Get("Authorization")
			if strings.HasPrefix(apiKey, "Bearer ") {
				apiKey = strings.TrimPrefix(apiKey, "Bearer ")
			}
		}

		// Проверяем хэш ключа
		if apiKey == "" || !validateAPIKey(apiKey) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="RSA Service"`)
			http.Error(w, `{"error": "Требуется авторизация", "code": "unauthorized"}`, http.StatusUnauthorized)
			
			// Логируем попытку неавторизованного доступа
			clientIP := r.RemoteAddr
			userAgent := r.UserAgent()
			log.Printf("🚫 Неавторизованный доступ к %s от %s (User-Agent: %s)", 
				r.URL.Path, clientIP, userAgent)
			return
		}

		// Авторизация успешна
		next.ServeHTTP(w, r)
	}
}

// Проверка API ключа
func validateAPIKey(apiKey string) bool {
	if config.APIKeyHash == "" {
		return false
	}

	// Вычисляем SHA256 хэш предоставленного ключа
	hash := sha256.Sum256([]byte(apiKey))
	hashHex := fmt.Sprintf("%x", hash)
	
	// Сравниваем хэши с постоянным временем выполнения
	return subtle.ConstantTimeCompare([]byte(hashHex), []byte(config.APIKeyHash)) == 1
}

// Генерация хэша для API ключа (утилитарная функция)
func GenerateAPIKeyHash(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	return fmt.Sprintf("%x", hash)
}

func autoDecryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Метод не поддерживается"}`, http.StatusMethodNotAllowed)
		return
	}

	// Проверяем, включена ли автоматическая расшифровка
	if !config.EnableDecrypt || privateKey == nil {
		http.Error(w, `{"error": "Автоматическая расшифровка отключена", "code": "decrypt_disabled"}`, 
			http.StatusForbidden)
		return
	}

	// Поддерживаем JSON
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		http.Error(w, `{"error": "Требуется Content-Type: application/json", "code": "invalid_content_type"}`, 
			http.StatusBadRequest)
		return
	}

	// Ограничение размера запроса (например, 64KB)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	// Обработка JSON запроса
	var request struct {
		EncryptedText string `json:"encrypted_text"`
		RequestID     string `json:"request_id,omitempty"` // Для отслеживания
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Неверный JSON формат: %s", "code": "invalid_json"}`, err.Error()), 
			http.StatusBadRequest)
		return
	}
	
	if request.EncryptedText == "" {
		http.Error(w, `{"error": "Поле 'encrypted_text' обязательно", "code": "missing_field"}`, 
			http.StatusBadRequest)
		return
	}
	
	// Проверка длины зашифрованного текста (предотвращение DoS)
	if len(request.EncryptedText) > 10000 {
		http.Error(w, `{"error": "Зашифрованный текст слишком длинный", "code": "text_too_long"}`, 
			http.StatusBadRequest)
		return
	}
	
	// Дешифруем
	decrypted, err := DecryptText(request.EncryptedText)
	if err != nil {
		// Не раскрываем детали ошибки для безопасности
		log.Printf("❌ Ошибка дешифрования (request_id: %s): %v", request.RequestID, err)
		http.Error(w, `{"error": "Ошибка дешифрования", "code": "decryption_failed"}`, 
			http.StatusBadRequest)
		return
	}
	
	// Возвращаем JSON ответ
	response := map[string]interface{}{
		"decrypted":       decrypted,
		"key_source":      "системный",
		"status":          "success",
		"request_id":      request.RequestID,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", request.RequestID)
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Настройка маршрутов
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler) // С передачей ключа - без авторизации
	
	// Автоматическая расшифровка с авторизацией
	http.HandleFunc("/auto-decrypt", authMiddleware(autoDecryptHandler))
	
	http.HandleFunc("/health", healthHandler)
	
	// Статические файлы
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Запуск сервера
	addr := ":" + config.Port
	log.Printf("🚀 RSA Encryptor/Decryptor Service запущен на http://localhost%s", addr)
	log.Printf("🔐 Публичный ключ: %s", config.PublicKeyPath)
	
	if config.EnableDecrypt {
		log.Printf("🔓 Приватный ключ: %s (автоматическая расшифровка ВКЛЮЧЕНА)", config.PrivateKeyPath)
		log.Printf("   POST /auto-decrypt - Автоматическая расшифровка (требуется авторизация)")
	} else {
		log.Printf("🔒 Автоматическая расшифровка ОТКЛЮЧЕНА")
	}
	
	if config.AuthEnabled {
		if config.APIKeyHash != "" {
			log.Printf("🔑 Авторизация ВКЛЮЧЕНА (API ключ установлен)")
		} else {
			log.Printf("⚠️  Авторизация ВКЛЮЧЕНА, но API_KEY_HASH не указан!")
		}
	}
	
	log.Printf("📡 Доступные эндпоинты:")
	log.Printf("   POST /encrypt        - Шифрование текста (публичный)")
	log.Printf("   POST /decrypt        - Дешифрование с передачей ключа (публичный)")
	log.Printf("   POST /auto-decrypt   - Автоматическая расшифровка (защищенный)")
	log.Printf("   GET  /health         - Проверка работоспособности (публичный)")
	log.Println("⚡ Готов к работе!")
	
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}