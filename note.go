package main

import "strings"

type Note struct {
	NoteId string `json:"noteId"`
	Text   string `json:"text"`
}

func stringToNote(s string) *Note {
	noteId := strings.Split(s, "%3A")[0]
	noteText := strings.Split(s, "%3A")[1]
	return &Note{NoteId: noteId, Text: noteText}

}
