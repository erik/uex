package irc

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"gopkg.in/sorcix/irc.v2"
	"gopkg.in/sorcix/irc.v2/ctcp"
)

const (
	serverBufferName  = "$server"
	mentionBufferName = "$mentions"

	inputFileName  = "in"
	outputFileName = "out"
)

// NetworkConfiguration contains the configuration for a connection to
// a single IRC network. Used by Client.
type NetworkConfiguration struct {
	Name                 string `json:"name"`
	Host                 string `json:"host"`
	Port                 int    `json:"port"`
	IsTLS                bool   `json:"is_tls"`
	SkipCertificateCheck bool   `json:"skip_certificate_check,omitempty"`

	Nick           string   `json:"nick"`
	RealName       string   `json:"real_name"`
	ServerPass     string   `json:"server_pass,omitempty"`
	OnConnect      []string `json:"on_connect"`
	RejoinExisting bool     `json:"rejoin_existing"`
}

// Client stores connection information and metadata for a connection
// to an IRC network.
type Client struct {
	NetworkConfiguration

	conn io.ReadWriteCloser
	mux  sync.Mutex

	buffers map[string]buffer

	directory string
}

type buffer struct {
	ch     chan message
	client *Client
	path   string

	name  string
	topic string

	// set of users that are present in the channel.
	users map[string]bool
}

// IRC message with a timestamp of when it was sent (possibly set by the server
// using the `server-time` capability)
type message struct {
	irc.Message
	ts time.Time
}

// wrapMessage is a simple convenience function for turning an irc.Message into
// a timestamped message. Assumes that the message was sent at the instance the
// function was called.
func wrapMessage(m irc.Message) message {
	return message{Message: m, ts: time.Now().Local()}
}

func NewClient(baseDir string, cfg NetworkConfiguration) *Client {
	client := &Client{
		NetworkConfiguration: cfg,

		directory: filepath.Join(baseDir, cfg.Name),
		buffers:   make(map[string]buffer),
	}

	return client
}

// Connect opens a TCP connection to the IRC network and sends `NICK`,
// `USER`, and `PASS` commands to authenticate the connection.
func (c *Client) Connect() error {
	if err := c.dial(); err != nil {
		return err
	}

	if c.ServerPass != "" {
		if err := c.send("PASS", c.ServerPass); err != nil {
			return err
		}
	}

	caps := []string{
		"znc.in/server-time-iso",
		"server-time",
	}

	for _, cap := range caps {
		c.send("CAP", "REQ", cap)
	}
	if err := c.sendRaw([]byte("CAP END")); err != nil {
		return err
	}

	realName := c.RealName
	if realName == "" {
		realName = c.Nick
	}

	if err := c.send("NICK", c.Nick); err != nil {
		return err
	}
	if err := c.send("USER", c.Nick, "*", "*", realName); err != nil {
		return err
	}

	return nil
}

// Listen loops through all IRC messages sent to the client as long as
// the connection remains open, dispatching to handlers. Will return
// an error if the connection is interrupted, or an unparseable
// message is returned.
func (c *Client) Listen() error {
	scanner := bufio.NewScanner(c.conn)
	for scanner.Scan() {
		line := scanner.Text()
		ts := time.Now()

		// sorcix/irc.v2 doesn't support IRCv3 tags. Parse them
		// ourselves and strip them out.
		if strings.HasPrefix(line, "@") {
			// split into (tags, line)
			parts := strings.SplitN(line, " ", 2)
			tags := parts[0][1:len(parts[0])]
			line = parts[1]

			for _, tag := range strings.Split(tags, ";") {
				kv := strings.SplitN(tag, "=", 2)
				switch kv[0] {
				case "time":
					ts, _ = time.Parse("2006-01-02T15:04:05.999Z", kv[1])
				}

			}
		}
		// UTC isn't useful here.
		ts = ts.Local()

		msg := irc.ParseMessage(line)
		if msg == nil {
			fmt.Printf("[%s] <-- invalid message: %s\n", c.Name, line)
			continue
		}

		fmt.Printf("[%s] <-- %+v\n", c.Name, msg)
		if err := c.handleMessage(message{
			Message: *msg,
			ts:      ts,
		}); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// dial handles the TCP/TLS details of connecting to an IRC network.
func (c *Client) dial() error {
	c.serverBuffer().writeInfoMessage("connecting ...")

	server := fmt.Sprintf("%s:%d", c.Host, c.Port)

	conn, err := net.Dial("tcp", server)
	if err != nil {
		return err
	}

	tcpc := conn.(*net.TCPConn)
	if err = tcpc.SetKeepAlive(true); err != nil {
		return err
	}
	if err = tcpc.SetKeepAlivePeriod(30 * time.Second); err != nil {
		return err
	}

	if c.IsTLS {
		conn = tls.Client(conn, &tls.Config{
			ServerName:         c.Host,
			InsecureSkipVerify: c.SkipCertificateCheck,
		})
	}

	c.conn = conn
	return nil
}

func (c *Client) send(cmd string, params ...string) error {
	msg := wrapMessage(irc.Message{
		Command: cmd,
		Params:  params,
	})

	return c.sendRaw(msg.Bytes())
}

func (c *Client) sendRaw(msg []byte) error {
	line := append(msg, '\r', '\n')

	if _, err := c.conn.Write(line); err != nil {
		log.Printf("Failed to write... %+v\n", err)
		return err
	}

	fmt.Printf("[%s] --> %+v\n", c.Name, string(msg))
	return nil
}

// listExistingChannels returns a list of channel names that were
// found in the client's output directory.
func (c *Client) listExistingChannels() []string {
	files, err := ioutil.ReadDir(c.directory)
	if err != nil {
		log.Fatal(err)
	}

	channels := []string{}
	for _, file := range files {
		name := file.Name()
		if isChannel(name) {
			channels = append(channels, name)
		}
	}

	return channels
}

func (c *Client) buffersContainingNick(nick string) []string {
	buffers := []string{}
	for name, buf := range c.buffers {
		if _, ok := buf.users[nick]; ok {
			buffers = append(buffers, name)
		}
	}

	return buffers
}

func (c *Client) handleMessage(msg message) error {
	buf := c.getBuffer(serverBufferName)

	switch msg.Command {
	case irc.RPL_WELCOME:
		for _, msg := range c.OnConnect {
			if err := c.sendRaw([]byte(msg)); err != nil {
				return err
			}
		}

		if c.RejoinExisting {
			for _, ch := range c.listExistingChannels() {
				if err := c.send(irc.JOIN, ch); err != nil {
					return err
				}
			}
		}

	case irc.PING:
		if err := c.send(irc.PONG, msg.Params...); err != nil {
			return err
		}

	case irc.PONG: // PONG #channel timestamp
		if len(msg.Params) != 2 {
			break
		}

		s := strings.SplitN(msg.Params[1], " ", 2)
		if len(s) != 2 {
			break
		}

		if ts, err := strconv.ParseInt(s[1], 10, 64); err == nil {
			delta := time.Duration(time.Now().UnixNano()-ts) / time.Millisecond
			text := fmt.Sprintf("PONG from %s: %d ms", msg.Params[0], delta)

			c.getBuffer(s[0]).writeInfoMessage(text)
			buf = nil
		}

	case irc.NICK:
		from := msg.Prefix.Name
		to := msg.Params[0]

		// Keep track of own renames.
		if from == c.Nick {
			c.Nick = to
		}

		line := fmt.Sprintf("%s changed nick to %s", from, to)

		buffers := c.buffersContainingNick(from)
		for _, name := range buffers {
			buf := c.getBuffer(name)
			delete(buf.users, from)
			buf.users[to] = true
			buf.writeInfoMessage(line)
		}

	case irc.JOIN:
		buf = c.getBuffer(msg.Params[0])
		buf.users[msg.Prefix.Name] = true

	case irc.PART:
		buf = c.getBuffer(msg.Params[0])
		delete(buf.users, msg.Prefix.Name)

		partMsg := "leaving"
		if len(msg.Params) > 1 {
			partMsg = msg.Params[1]
		}

		line := fmt.Sprintf("%s part: %s", msg.Prefix.Name, partMsg)
		buf.writeInfoMessage(line)

	case irc.QUIT:
		who := msg.Prefix.Name
		line := fmt.Sprintf("%s quit: %s", who, msg.Params[0])

		buffers := c.buffersContainingNick(who)
		for _, name := range buffers {
			buf := c.getBuffer(name)
			delete(buf.users, who)
			buf.writeInfoMessage(line)
		}

		buf = nil

	case irc.RPL_NAMREPLY:
		target := msg.Params[2]
		names := strings.Split(msg.Trailing(), " ")
		buf = c.getBuffer(target)

		for i := range names {
			nick := normalizeNick(names[i])
			buf.users[nick] = true
		}

		buf = nil

	case irc.PRIVMSG, irc.NOTICE:
		target := msg.Params[0]
		isMention := false

		// Group all messages sent by the server together,
		// regardless of server name.
		//
		// For direct messages, we want to look at the sender.
		if msg.Prefix.IsServer() {
			target = serverBufferName
		} else if !isChannel(target) {
			target = msg.Prefix.Name
			// All direct messages should be considered mentions
			isMention = true
		} else if c.shouldHighlight(msg.Trailing()) {
			isMention = true
		}

		if isMention {
			mention := msg
			// Copy so we don't clobber the original
			mention.Params = make([]string, len(mention.Params))
			copy(mention.Params, msg.Params)
			mention.Params[len(mention.Params)-1] = fmt.Sprintf("[%s]: %s", target, msg.Trailing())
			c.mentionBuffer().ch <- mention
		}

		buf = c.getBuffer(target)

	case irc.RPL_TOPIC:
		target := msg.Params[1]
		topic := msg.Params[2]

		buf = c.getBuffer(target)
		buf.topic = topic

	case irc.ERR_NICKNAMEINUSE:
		c.Nick = c.Nick + "`"
		fmt.Printf("Nick in use, trying '%s'\n", c.Nick)
		if err := c.send("NICK", c.Nick); err != nil {
			return err
		}

	case irc.MODE:
		who := msg.Prefix.Name
		target := msg.Params[0]
		mode := strings.Join(msg.Params[1:], " ")

		line := fmt.Sprintf("%s set mode for %s: %s", who, target, mode)

		if !isChannel(target) {
			target = serverBufferName
		}

		buf = c.getBuffer(target)
		buf.writeInfoMessage(line)

		buf = nil

	case irc.ERROR:
		msg := strings.Join(msg.Params[1:], " ")

		line := fmt.Sprintf("[ERROR]: %s", msg)

		c.serverBuffer().writeInfoMessage(line)
		c.serverBuffer().writeInfoMessage("attempting reconnect...")

		return fmt.Errorf("Network sent ERROR msg: %s", msg)
	}

	if buf != nil {
		buf.ch <- msg
	}

	return nil
}

func (c *Client) serverBuffer() *buffer {
	return c.getBuffer(serverBufferName)
}

func (c *Client) mentionBuffer() *buffer {
	return c.getBuffer(mentionBufferName)
}

func (c *Client) getBuffer(name string) *buffer {
	c.mux.Lock()
	defer c.mux.Unlock()

	name = normalizeBufferName(name)

	// Sent early on, at least by freenode.
	if name == "*" {
		name = serverBufferName
	}

	if buf, exists := c.buffers[name]; exists {
		return &buf
	}

	path := c.directory
        path = filepath.Join(path, name)

	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	c.buffers[name] = buffer{
		ch:     make(chan message),
		client: c,
		path:   path,

		name:  name,
		topic: "",
		users: make(map[string]bool),
	}

	buf := c.buffers[name]

	go buf.inputHandler()
	go buf.outputHandler()

	return &buf
}

func (c *Client) handleInputLine(bufName, line string) error {
	fmt.Printf("[%s/%s] >> %s\n", c.Name, bufName, line)

	cmd, rest := splitInputCommand(bufName, line)

	switch cmd {
	case "/m", "/msg":
		s := strings.SplitN(rest, " ", 2)
		if len(s) != 2 {
			c.serverBuffer().writeInfoMessage("expected: /msg TARGET MESSAGE")
			return nil
		} else if s[0] == serverBufferName {
			c.serverBuffer().writeInfoMessage("can't PRIVMSG a server.")
			return nil
		} else if s[0] == mentionBufferName {
			c.mentionBuffer().writeInfoMessage("can't PRIVMSG your mentions.")
			return nil
		}

		buf := c.getBuffer(s[0])
		buf.ch <- wrapMessage(irc.Message{
			Prefix:  &irc.Prefix{Name: c.Nick},
			Command: irc.PRIVMSG,
			Params:  []string{s[1]},
		})

		return c.send("PRIVMSG", s[0], s[1])

	case "/me":
		action := ctcp.Action(rest)

		buf := c.getBuffer(bufName)
		buf.ch <- wrapMessage(irc.Message{
			Prefix:  &irc.Prefix{Name: c.Nick},
			Command: irc.PRIVMSG,
			Params:  []string{action},
		})

		return c.send("PRIVMSG", bufName, action)

	case "/j", "/join":
		if !isChannel(rest) {
			c.getBuffer(bufName).writeInfoMessage("expected: /join TARGET")
			return nil
		}
		return c.send("JOIN", rest)

	case "/l", "/list":
		buf := c.getBuffer(bufName)

		buf.writeInfoMessage("~~ buffers ~~")
		for k := range c.buffers {
			buf.writeInfoMessage(" " + k)
		}

	case "/ping":
		ts := time.Now().UnixNano()
		return c.send("PING", fmt.Sprintf("%s %d", bufName, ts))
	case "/quote":
		params := strings.Split(rest, " ")
		if len(params) == 1 {
			return c.send(params[0])
		} else {
			return c.send(params[0], params[1:]...)
		}

	case "/r", "/reconnect":
		c.serverBuffer().writeInfoMessage("... disconnecting")
		if err := c.conn.Close(); err != nil {
			fmt.Printf("failed to close: %+v\n", err)
			return err
		}

	default:
		text := fmt.Sprintf("Unknown command: %s %s", cmd, rest)
		c.getBuffer(bufName).writeInfoMessage(text)
	}
	return nil
}

func (b *buffer) outputHandler() {
	name := filepath.Join(b.path, outputFileName)
	mode := os.O_APPEND | os.O_RDWR | os.O_CREATE
	file, err := os.OpenFile(name, mode, 0644)
	if err != nil {
		log.Fatalf("failed to create output file: %+v\n", err)
	}

	defer file.Close()

	// Keep track of the date of the last message so that we can add
	// formatting for day changes.
	currentDate := time.Time{}

	// TODO: better serialization?? etc.
	for msg := range b.ch {
		text := b.client.formatMessage(msg, &currentDate)
		if text == "" {
			continue
		}

		if _, err := file.WriteString(text + "\n"); err != nil {
			log.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			log.Fatal(err)
		}
	}
}

func (b *buffer) writeInfoMessage(msg string) {
	b.ch <- wrapMessage(irc.Message{
		Prefix:  &irc.Prefix{Name: "uex"},
		Command: "*",
		Params:  []string{msg},
	})
}

func (b *buffer) inputHandler() {
	name := filepath.Join(b.path, inputFileName)
	err := syscall.Mkfifo(name, 0777)

	// Doesn't matter if the FIFO already exists from a previous run.
	if err != nil && err != syscall.EEXIST {
		log.Fatal(err)
	}

	for {
		buf, err := ioutil.ReadFile(name)
		if err != nil {
			log.Fatal(err)
		}

		if len(buf) == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		lines := strings.Split(string(buf), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			b.client.handleInputLine(b.name, line)
		}
	}
}

func isChannel(target string) bool {
	if target == "" {
		return false
	}

	return target[0] == '#' || target[0] == '&'
}

// normalizeBufferName strips out illegal characters and standardizes
// naming so that it's safe to write as a directory name to the file
// system.
func normalizeBufferName(buffer string) string {
	return strings.Map(func(ch rune) rune {
		if unicode.IsLetter(ch) || unicode.IsNumber(ch) {
			return unicode.ToLower(ch)
		} else if strings.ContainsRune("$*.#&+!-", ch) {
			return ch
		}

		return '_'
	}, buffer)
}

// normalizeNick strips off user mode characters
func normalizeNick(nick string) string {
	return strings.TrimLeftFunc(nick, func(ch rune) bool {
		switch ch {
		case '%', '@', '~', '\\', '+':
			return true
		}

		return false
	})
}

// splitInputCommand returns `(command, param)` for a line of input
// received from the user. If no command is explicitly specified,
// assume "/msg" (i.e. PRIVMSG).
func splitInputCommand(bufName, line string) (string, string) {
	// Without a prefix, it's just a regular PRIVMSG
	if !strings.HasPrefix(line, "/") {
		return "/msg", bufName + " " + line
	}
	// Double slash at start means privmsg with leading slash
	if strings.HasPrefix(line, "//") {
		return "/msg", bufName + " " + line[1:]
	}

	s := strings.SplitN(line, " ", 2)
	cmd := strings.ToLower(s[0])

	if len(s) == 1 {
		return cmd, ""
	}

	return cmd, s[1]
}
