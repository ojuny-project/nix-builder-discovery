package hook

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func writeUint(buffer *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], value)
	buffer.Write(raw[:])
}

func writeString(buffer *bytes.Buffer, value string) {
	writeUint(buffer, uint64(len(value)))
	buffer.WriteString(value)
	if padding := (8 - len(value)%8) % 8; padding > 0 {
		buffer.Write(make([]byte, padding))
	}
}

func writeStrings(buffer *bytes.Buffer, values []string) {
	writeUint(buffer, uint64(len(values)))
	for _, value := range values {
		writeString(buffer, value)
	}
}

func TestReadSettingsAndJob(t *testing.T) {
	var buffer bytes.Buffer

	writeUint(&buffer, 1)
	writeString(&buffer, "sandbox")
	writeString(&buffer, "true")
	writeUint(&buffer, 0)

	writeString(&buffer, "try")
	writeUint(&buffer, 1)
	writeString(&buffer, "x86_64-linux")
	writeString(&buffer, "/nix/store/abc-nbd-smoke.drv")
	writeStrings(&buffer, []string{"kvm", "big-parallel"})

	source := &source{reader: bufio.NewReader(&buffer)}

	if err := source.readSettings(); err != nil {
		t.Fatalf("settings: %v", err)
	}

	job, err := source.readJob()
	if err != nil {
		t.Fatalf("job: %v", err)
	}

	if job.system != "x86_64-linux" {
		t.Fatalf("system = %q", job.system)
	}
	if job.drvPath != "/nix/store/abc-nbd-smoke.drv" {
		t.Fatalf("drv = %q", job.drvPath)
	}
	if len(job.features) != 2 || job.features[0] != "kvm" {
		t.Fatalf("features = %#v", job.features)
	}
}

func TestReadJobRejectsUnknownKind(t *testing.T) {
	var buffer bytes.Buffer
	writeString(&buffer, "not-a-job")

	source := &source{reader: bufio.NewReader(&buffer)}
	if _, err := source.readJob(); err == nil {
		t.Fatal("expected an unknown job kind to be rejected")
	}
}

func TestReadStringPadding(t *testing.T) {
	var buffer bytes.Buffer
	writeString(&buffer, "abc")
	writeUint(&buffer, 42)

	source := &source{reader: bufio.NewReader(&buffer)}

	value, err := source.readString()
	if err != nil {
		t.Fatalf("string: %v", err)
	}
	if value != "abc" {
		t.Fatalf("value = %q", value)
	}

	number, err := source.readUint64()
	if err != nil {
		t.Fatalf("number: %v", err)
	}
	if number != 42 {
		t.Fatalf("number = %d", number)
	}
}
