package ldap

import (
	
	"fmt"
	"bytes"
	"io/ioutil"
	"encoding/binary"
	"encoding/base64"

	"github.com/softlandia/cpd"
	ber "github.com/go-asn1-ber/asn1-ber"
   
)

type NtlmBindResult struct {
    DomainName   string
	UserName     string
	Workstation  string
	Authenticated bool
}


func (l *Conn) buildNtlmPacket(message []byte) *ber.Packet {

	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "Authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSS-SPNEGO", "Mechanism"))
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(message), "Credentials"))

	request.AppendChild(auth)

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
	packet.AppendChild(request)

	return packet
}

func (l *Conn) NtlmType1MsgReq(message []byte) (string, error) {

	packet := l.buildNtlmPacket(message)
	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return "", err
	}

	respPacket, err := l.readPacket(msgCtx)
	if err != nil {
		return "", err
	}

	if len(respPacket.Children) >= 2 {

		if len(respPacket.Children[1].Children) >= 4 {
			
			child := respPacket.Children[1].Children[3]
			if child.Tag != ber.TagObjectDescriptor {
				return "", GetLDAPError(respPacket)
			}
			if child.Data == nil {
				return "", GetLDAPError(respPacket)
			}
			data, err := ioutil.ReadAll(child.Data)
		
			return base64.StdEncoding.EncodeToString(data), err
		}

	}

	return "", fmt.Errorf("Ldap ntlm auth get type 2 Message error.")

}

func (l *Conn) NtlmType3MsgReq(message []byte) (*NtlmBindResult, error) {

	bindResult := &NtlmBindResult{
		Authenticated: false,
	}
	msgLen := uint16(len(message))
	if msgLen <= 52 {
		return bindResult, fmt.Errorf("Ldap ntlm auth request type 3 Message error: Invalid message format.")
	}

	var userLen, hostLen, domainLen, userOffset, hostOffset, domainOffset uint16

	binary.Read(bytes.NewBuffer(message[28:30]), binary.LittleEndian, &domainLen)
	binary.Read(bytes.NewBuffer(message[32:34]), binary.LittleEndian, &domainOffset)
	binary.Read(bytes.NewBuffer(message[36:38]), binary.LittleEndian, &userLen)
	binary.Read(bytes.NewBuffer(message[40:42]), binary.LittleEndian, &userOffset)
	binary.Read(bytes.NewBuffer(message[44:46]), binary.LittleEndian, &hostLen)
	binary.Read(bytes.NewBuffer(message[48:50]), binary.LittleEndian, &hostOffset)

	domainEnd := domainOffset + domainLen
	userEnd := userOffset + userLen
	hostEnd := hostOffset + hostLen

	if msgLen < domainEnd || msgLen < userEnd || msgLen < hostEnd {
		return bindResult, fmt.Errorf("Ldap ntlm auth request type 3 Message error: Invalid message format.")
	}
	
	bindResult.DomainName = cpd.DecodeUTF16le(string(message[domainOffset:domainEnd]))
	bindResult.UserName = cpd.DecodeUTF16le(string(message[userOffset:userEnd]))
	bindResult.Workstation = cpd.DecodeUTF16le(string(message[hostOffset:hostEnd]))

	packet := l.buildNtlmPacket(message)
	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return bindResult, err
	}

	respPacket, err := l.readPacket(msgCtx)
	if err != nil {
		return bindResult, err
	}

	if len(respPacket.Children) >= 2 {

		if len(respPacket.Children[1].Children) >= 1 {

			resultCode := uint16(respPacket.Children[1].Children[0].Value.(int64))
		
			if resultCode == 0 {
				bindResult.Authenticated = true
			}
			return bindResult, err
		}

	}

	return bindResult, fmt.Errorf("Ldap ntlm auth request type 3 Message error: Invalid packet format.")
	
}