package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	http.HandleFunc("/signUp", signUp)
	http.HandleFunc("/addNote", addNote)
	http.HandleFunc("/signIn", signIn)
	http.HandleFunc("/getNotes", getAllNotes)
	http.HandleFunc("/updateNote", updateNote)
	http.HandleFunc("/deleteNote", deleteNote)
	http.ListenAndServe(":8081", nil)
}

/*
Deletes a note by noteId
1) Parse Whole notes file for current user into hashmap and removes note with given NoteId
2) After deleting note from map inputs map back into text file
*/
func deleteNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !isTokenValid(w, r) {
		return
	}
	if !userExists(w, r) {
		return
	}
	user := getCurrentUser(r)
	notedId := r.PostForm.Get("noteId")
	file, err := os.OpenFile(user.UserId, os.O_RDONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		http.Error(w, "Error Getting Notes", http.StatusInternalServerError)
		return
	}
	rawNotes := make([]byte, 99999)
	n, err := file.Read(rawNotes)
	if err != nil {
		http.Error(w, "Error Getting Notes", http.StatusInternalServerError)
		return
	}
	notesMap := make(map[string]string, 0)
	notesArray := strings.Split(string(rawNotes[:n]), "\n")
	for i, noteString := range notesArray {
		if i == len(notesArray)-1 {
			break
		}
		note := stringToNote(noteString)
		notesMap[note.NoteId] = note.Text
	}
	if _, contains := notesMap[notedId]; !contains {
		http.Error(w, "Note Not found", http.StatusNotFound)
		return
	}
	delete(notesMap, notedId)

	notesArray = make([]string, 0)
	for id, text := range notesMap {
		noteString := id + "%3A" + text
		notesArray = append(notesArray, noteString)
	}
	ioutil.WriteFile(user.UserId, []byte(strings.Join(notesArray, "\n")+"\n"), 0666)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Note Deleted Successfully")
}

/*
Updates Note by NoteId
1) Parse Whole notes file for current user into hashmap and updates note with given NoteId
2) After updating note, it inputs map back into text file
*/
func updateNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !isTokenValid(w, r) {
		return
	}
	if !userExists(w, r) {
		return
	}
	user := getCurrentUser(r)
	notedId := r.PostForm.Get("noteId")
	noteText := r.PostForm.Get("text")
	file, err := os.OpenFile(user.UserId, os.O_RDONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		http.Error(w, "Error Getting Notes", http.StatusInternalServerError)
		return
	}
	rawNotes := make([]byte, 99999)
	n, err := file.Read(rawNotes)
	if err != nil {
		http.Error(w, "Error Getting Notes", http.StatusInternalServerError)
		return
	}
	notesMap := make(map[string]string, 0)
	notesArray := strings.Split(string(rawNotes[:n]), "\n")
	for i, noteString := range notesArray {
		if i == len(notesArray)-1 {
			break
		}
		note := stringToNote(noteString)
		notesMap[note.NoteId] = note.Text
	}
	if _, contains := notesMap[notedId]; !contains {
		http.Error(w, "Note Not found", http.StatusNotFound)
		return
	}
	notesMap[notedId] = noteText
	notesArray = make([]string, 0)
	for id, text := range notesMap {
		noteString := id + "%3A" + text
		notesArray = append(notesArray, noteString)
	}
	ioutil.WriteFile(user.UserId, []byte(strings.Join(notesArray, "\n")+"\n"), 0666)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Note Updated Successfully")
}

/*
Get All notes for a given user
1) Parses the note text file for current user and returns jsonarray for note struct
*/
func getAllNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !isTokenValid(w, r) {
		return
	}
	if !userExists(w, r) {
		return
	}
	user := getCurrentUser(r)

	file, err := os.OpenFile(user.UserId, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		http.Error(w, "Error Getting Notes", http.StatusInternalServerError)
		return
	}
	rawNotes := make([]byte, 99999)
	n, err := file.Read(rawNotes)
	if err != nil {
		http.Error(w, "Error Getting Notes", http.StatusInternalServerError)
		return
	}

	notesMap := strings.Split(string(rawNotes[:n]), "\n")
	notes := []Note{}
	for i, noteString := range notesMap {
		if i == len(notesMap)-1 {
			break
		}
		note := Note{NoteId: strings.Split(noteString, "%3A")[0], Text: strings.Split(noteString, "%3A")[1]}
		notes = append(notes, note)
	}
	res, err := json.Marshal(notes)
	if err != nil {
		http.Error(w, "Error Getting Notes", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, string(res))
	return
}

/*
Appends note to user notes file
*/
func addNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !isTokenValid(w, r) {
		return
	}
	if !userExists(w, r) {
		return
	}

	user := getCurrentUser(r)
	file, err := os.OpenFile(user.UserId, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		http.Error(w, "Error Adding Note", http.StatusInternalServerError)
		fmt.Println(err)
		return
	}
	r.ParseForm()
	note := r.PostForm.Get("note")
	if note == "" {
		http.Error(w, "Empty Note Cannot be Added", http.StatusBadRequest)
		return
	}
	currentTime := time.Now().UnixMicro()
	note = strconv.FormatInt(currentTime, 10) + "%3A" + note + "\n"
	_, err = file.Write([]byte(note))
	if err != nil {
		http.Error(w, "Error Adding Note", http.StatusInternalServerError)
		fmt.Println(err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Note Sucesfully Added")
	return
}

/*
Returns current user struct based on authrorization header
*/
func getCurrentUser(r *http.Request) *User {
	token := r.Header.Get("authorization")
	decodedString, _ := base64.StdEncoding.DecodeString(token)
	dataArray := strings.Split(string(decodedString), ", ")
	user := User{}
	user.Email = dataArray[0]
	user.Password = dataArray[1]
	user.UserId = dataArray[2]
	return &user
}

/*
finds whether authorization header received is valid
1) If authrorization header exists
2) if token is valid
3) if token is expired or not
*/
func isTokenValid(w http.ResponseWriter, r *http.Request) bool {
	r.ParseForm()
	token := r.Header.Get("authorization")
	if token == "" {
		http.Error(w, "Authorization Token Not found", http.StatusUnauthorized)
		return false
	}
	decodedString, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return false
	}
	expiryTime := strings.Split(string(decodedString), ", ")
	expiryTimeInt, _ := strconv.ParseInt(expiryTime[3], 10, 64)
	if expiryTimeInt < time.Now().UnixMilli() {
		http.Error(w, "Token Expired", http.StatusUnauthorized)
		return false
	}
	return true
}

/*
finds whether current user exist or not
*/
func userExists(w http.ResponseWriter, r *http.Request) bool {
	r.ParseForm()
	token := r.Header.Get("authorization")
	decodedString, _ := base64.StdEncoding.DecodeString(token)
	dataArray := strings.Split(string(decodedString), ", ")
	user := User{}
	user.Email = dataArray[0]
	user.Password = dataArray[1]
	file, error := os.OpenFile("Users", os.O_RDONLY, 0666)
	if error != nil {
		http.Error(w, "Error Opening File", http.StatusInternalServerError)
		fmt.Println(error)
		return false
	}
	rawData := make([]byte, 9999)
	file.Read(rawData)
	userString := string(rawData)
	userArray := strings.Split(userString, "\n")

	for _, userDetails := range userArray {
		userDetailArray := strings.Split(userDetails, ", ")
		email := userDetailArray[0]
		password := userDetailArray[1]
		if strings.Compare(email, user.Email) == 0 && strings.Compare(password, user.Password) == 0 {
			return true
		}
	}
	http.Error(w, "Invalid User", http.StatusUnauthorized)
	return false
}

/*
Signs Up the user
1) Parses get request body
2) Adds current user credentials into User file
*/
func signUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		email := r.URL.Query().Get("email")
		password := r.URL.Query().Get("password")
		if email == "" || password == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
		}
		if !validateEmailAndPassword(password, email) {
			http.Error(w, "Email or Password contains special characters", http.StatusBadRequest)
			return
		}
		file, err := os.OpenFile("Users", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
		userId := time.Now().UnixNano()
		userString := email + ", " + password + ", " + strconv.FormatInt(userId, 10) + ", "
		if err != nil {
			http.Error(w, "Error Opening File", http.StatusInternalServerError)
			fmt.Println(err)
			return
		}
		file.Write([]byte(userString))
		file.Close()
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "User Successfully created")
	} else {
		http.Error(w, "Bad Request", http.StatusBadRequest)
	}
}

/*
Sign in the user
1) Verifies if user exists by matching credentials
2) Return a authorization token which is valid for next 60 min
*/
func signIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var user User = User{}

		r.ParseForm()
		user.Email = r.PostForm.Get("email")
		user.Password = r.PostForm.Get("password")
		if user.Email == "" || user.Password == "" {
			http.Error(w, "Error Parsing Body", http.StatusBadRequest)
			return
		}
		file, error := os.OpenFile("Users", os.O_RDONLY, 0666)
		if error != nil {
			http.Error(w, "Error Opening File", http.StatusInternalServerError)
			fmt.Println(error)
			return
		}
		rawData := make([]byte, 9999)
		file.Read(rawData)
		userString := string(rawData)
		userArray := strings.Split(userString, "\n")

		for _, userDetails := range userArray {
			userDetailArray := strings.Split(userDetails, ", ")
			email := userDetailArray[0]
			password := userDetailArray[1]
			userId := userDetailArray[2]
			if strings.Compare(email, user.Email) == 0 && strings.Compare(password, user.Password) == 0 {
				ExpiryTime := time.Now().UnixMilli() + 3600000
				tokenString := email + ", " + password + ", " + userId + ", " + strconv.FormatInt(ExpiryTime, 10)
				tokenEncoded := base64.StdEncoding.EncodeToString([]byte(tokenString))
				w.WriteHeader(http.StatusAccepted)
				fmt.Fprint(w, tokenEncoded)
				return
			}
		}

		http.Error(w, "User Not Found", http.StatusNotFound)
	} else {
		http.Error(w, "Bad Request", http.StatusBadRequest)
	}
}

/*
Validates if email and password are formatted (Should'nt contain ",", we user "," in our code logic to store in file)
*/
func validateEmailAndPassword(password, email string) bool {
	for _, char := range password {
		if char == ',' {
			return false
		}

	}
	for _, char := range email {
		if char == ',' {
			return false
		}

	}
	return true
}
