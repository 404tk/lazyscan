package lib

import (
	"fmt"
	"math"

	"github.com/golang/protobuf/proto"
)

type Poc struct {
	Name    string              `yaml:"name"`
	Set     map[string]string   `yaml:"set"`
	Sets    map[string][]string `yaml:"sets"`
	Rules   []Rules             `yaml:"rules"`
	Groups  map[string][]Rules  `yaml:"groups"`
	Exploit []Rules             `yaml:"exploit"`
	Exec    []Rules             `yaml:"exec"`
	Detail  Detail              `yaml:"detail"`
}

type Rules struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
}

type Detail struct {
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type UrlType struct {
	Scheme               string   `protobuf:"bytes,1,opt,name=scheme,proto3" json:"scheme,omitempty"`
	Domain               string   `protobuf:"bytes,2,opt,name=domain,proto3" json:"domain,omitempty"`
	Host                 string   `protobuf:"bytes,3,opt,name=host,proto3" json:"host,omitempty"`
	Port                 string   `protobuf:"bytes,4,opt,name=port,proto3" json:"port,omitempty"`
	Path                 string   `protobuf:"bytes,5,opt,name=path,proto3" json:"path,omitempty"`
	Query                string   `protobuf:"bytes,6,opt,name=query,proto3" json:"query,omitempty"`
	Fragment             string   `protobuf:"bytes,7,opt,name=fragment,proto3" json:"fragment,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UrlType) Reset()         { *m = UrlType{} }
func (m *UrlType) String() string { return proto.CompactTextString(m) }
func (*UrlType) ProtoMessage()    {}
func (*UrlType) Descriptor() ([]byte, []int) {
	return fileDescriptor_11b04836674e6f94, []int{0}
}

func (m *UrlType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UrlType.Unmarshal(m, b)
}
func (m *UrlType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UrlType.Marshal(b, m, deterministic)
}
func (m *UrlType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UrlType.Merge(m, src)
}
func (m *UrlType) XXX_Size() int {
	return xxx_messageInfo_UrlType.Size(m)
}
func (m *UrlType) XXX_DiscardUnknown() {
	xxx_messageInfo_UrlType.DiscardUnknown(m)
}

var xxx_messageInfo_UrlType proto.InternalMessageInfo

func (m *UrlType) GetScheme() string {
	if m != nil {
		return m.Scheme
	}
	return ""
}

func (m *UrlType) GetDomain() string {
	if m != nil {
		return m.Domain
	}
	return ""
}

func (m *UrlType) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *UrlType) GetPort() string {
	if m != nil {
		return m.Port
	}
	return ""
}

func (m *UrlType) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *UrlType) GetQuery() string {
	if m != nil {
		return m.Query
	}
	return ""
}

func (m *UrlType) GetFragment() string {
	if m != nil {
		return m.Fragment
	}
	return ""
}

type Request struct {
	Url                  *UrlType          `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	Method               string            `protobuf:"bytes,2,opt,name=method,proto3" json:"method,omitempty"`
	Headers              map[string]string `protobuf:"bytes,3,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	ContentType          string            `protobuf:"bytes,4,opt,name=content_type,json=contentType,proto3" json:"content_type,omitempty"`
	Body                 []byte            `protobuf:"bytes,5,opt,name=body,proto3" json:"body,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Request) Reset()         { *m = Request{} }
func (m *Request) String() string { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()    {}
func (*Request) Descriptor() ([]byte, []int) {
	return fileDescriptor_11b04836674e6f94, []int{1}
}

func (m *Request) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Request.Unmarshal(m, b)
}
func (m *Request) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Request.Marshal(b, m, deterministic)
}
func (m *Request) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Request.Merge(m, src)
}
func (m *Request) XXX_Size() int {
	return xxx_messageInfo_Request.Size(m)
}
func (m *Request) XXX_DiscardUnknown() {
	xxx_messageInfo_Request.DiscardUnknown(m)
}

var xxx_messageInfo_Request proto.InternalMessageInfo

func (m *Request) GetUrl() *UrlType {
	if m != nil {
		return m.Url
	}
	return nil
}

func (m *Request) GetMethod() string {
	if m != nil {
		return m.Method
	}
	return ""
}

func (m *Request) GetHeaders() map[string]string {
	if m != nil {
		return m.Headers
	}
	return nil
}

func (m *Request) GetContentType() string {
	if m != nil {
		return m.ContentType
	}
	return ""
}

func (m *Request) GetBody() []byte {
	if m != nil {
		return m.Body
	}
	return nil
}

type Response struct {
	Url                  *UrlType          `protobuf:"bytes,1,opt,name=url,proto3" json:"url,omitempty"`
	Status               int32             `protobuf:"varint,2,opt,name=status,proto3" json:"status,omitempty"`
	Headers              map[string]string `protobuf:"bytes,3,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	ContentType          string            `protobuf:"bytes,4,opt,name=content_type,json=contentType,proto3" json:"content_type,omitempty"`
	Body                 []byte            `protobuf:"bytes,5,opt,name=body,proto3" json:"body,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Response) Reset()         { *m = Response{} }
func (m *Response) String() string { return proto.CompactTextString(m) }
func (*Response) ProtoMessage()    {}
func (*Response) Descriptor() ([]byte, []int) {
	return fileDescriptor_11b04836674e6f94, []int{2}
}

func (m *Response) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Response.Unmarshal(m, b)
}
func (m *Response) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Response.Marshal(b, m, deterministic)
}
func (m *Response) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Response.Merge(m, src)
}
func (m *Response) XXX_Size() int {
	return xxx_messageInfo_Response.Size(m)
}
func (m *Response) XXX_DiscardUnknown() {
	xxx_messageInfo_Response.DiscardUnknown(m)
}

var xxx_messageInfo_Response proto.InternalMessageInfo

func (m *Response) GetUrl() *UrlType {
	if m != nil {
		return m.Url
	}
	return nil
}

func (m *Response) GetStatus() int32 {
	if m != nil {
		return m.Status
	}
	return 0
}

func (m *Response) GetHeaders() map[string]string {
	if m != nil {
		return m.Headers
	}
	return nil
}

func (m *Response) GetContentType() string {
	if m != nil {
		return m.ContentType
	}
	return ""
}

func (m *Response) GetBody() []byte {
	if m != nil {
		return m.Body
	}
	return nil
}

func init() {
	proto.RegisterType((*UrlType)(nil), "lib.UrlType")
	proto.RegisterType((*Request)(nil), "lib.Request")
	proto.RegisterMapType((map[string]string)(nil), "lib.Request.HeadersEntry")
	proto.RegisterType((*Response)(nil), "lib.Response")
	proto.RegisterMapType((map[string]string)(nil), "lib.Response.HeadersEntry")
}

func init() {
	proto.RegisterFile("http.proto", fileDescriptor_11b04836674e6f94)
}

var fileDescriptor_11b04836674e6f94 = []byte{
	// 378 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcc, 0x93, 0xb1, 0x8e, 0xd3, 0x40,
	0x10, 0x86, 0x65, 0x3b, 0x89, 0xc3, 0xc4, 0x42, 0x68, 0x05, 0x68, 0x49, 0x81, 0x8e, 0x54, 0x57,
	0x59, 0xe2, 0x8e, 0x02, 0x5d, 0x0d, 0x12, 0x15, 0xc5, 0x02, 0xb5, 0xb5, 0x3e, 0x0f, 0xd8, 0xc2,
	0xf6, 0x6e, 0x76, 0xc7, 0x91, 0xdc, 0xf3, 0x2e, 0x3c, 0x1b, 0xe2, 0x25, 0x90, 0x67, 0x37, 0x08,
	0x21, 0x8a, 0x94, 0x74, 0xf3, 0xff, 0xbf, 0x3d, 0x9a, 0x6f, 0x3c, 0x06, 0x68, 0x89, 0x6c, 0x69,
	0x9d, 0x21, 0x23, 0xb2, 0xbe, 0xab, 0x0f, 0xdf, 0x13, 0xc8, 0x3f, 0xb9, 0xfe, 0xe3, 0x6c, 0x51,
	0x3c, 0x85, 0x8d, 0xbf, 0x6f, 0x71, 0x40, 0x99, 0x5c, 0x25, 0xd7, 0x0f, 0x54, 0x54, 0x8b, 0xdf,
	0x98, 0x41, 0x77, 0xa3, 0x4c, 0x83, 0x1f, 0x94, 0x10, 0xb0, 0x6a, 0x8d, 0x27, 0x99, 0xb1, 0xcb,
	0xf5, 0xe2, 0x59, 0xe3, 0x48, 0xae, 0x82, 0xb7, 0xd4, 0xec, 0x69, 0x6a, 0xe5, 0x3a, 0x7a, 0x9a,
	0x5a, 0xf1, 0x18, 0xd6, 0xc7, 0x09, 0xdd, 0x2c, 0x37, 0x6c, 0x06, 0x21, 0xf6, 0xb0, 0xfd, 0xec,
	0xf4, 0x97, 0x01, 0x47, 0x92, 0x39, 0x07, 0xbf, 0xf5, 0xe1, 0x47, 0x02, 0xb9, 0xc2, 0xe3, 0x84,
	0x9e, 0xc4, 0x73, 0xc8, 0x26, 0xd7, 0xf3, 0x98, 0xbb, 0x9b, 0xa2, 0xec, 0xbb, 0xba, 0x8c, 0x10,
	0x6a, 0x09, 0x96, 0x89, 0x07, 0xa4, 0xd6, 0x34, 0xe7, 0x89, 0x83, 0x12, 0xb7, 0x90, 0xb7, 0xa8,
	0x1b, 0x74, 0x5e, 0x66, 0x57, 0xd9, 0xf5, 0xee, 0xe6, 0x19, 0xbf, 0x1b, 0xdb, 0x96, 0xef, 0x42,
	0xf6, 0x76, 0x24, 0x37, 0xab, 0xf3, 0x93, 0xe2, 0x05, 0x14, 0xf7, 0x66, 0x24, 0x1c, 0xa9, 0xa2,
	0xd9, 0x62, 0x44, 0xdb, 0x45, 0x8f, 0x37, 0x27, 0x60, 0x55, 0x9b, 0x66, 0x66, 0xc2, 0x42, 0x71,
	0xbd, 0xbf, 0x83, 0xe2, 0xcf, 0x7e, 0xe2, 0x11, 0x64, 0x5f, 0x71, 0x8e, 0xab, 0x5d, 0xca, 0x65,
	0x07, 0x27, 0xdd, 0x4f, 0x18, 0x87, 0x0c, 0xe2, 0x2e, 0x7d, 0x9d, 0x1c, 0x7e, 0x26, 0xb0, 0x55,
	0xe8, 0xad, 0x19, 0x3d, 0x5e, 0x02, 0xeb, 0x49, 0xd3, 0xe4, 0xb9, 0xcf, 0x5a, 0x45, 0x25, 0x5e,
	0xfd, 0x0d, 0xbb, 0x8f, 0xb0, 0xa1, 0xef, 0xff, 0x43, 0xfb, 0x8d, 0xbf, 0xec, 0x09, 0xdd, 0x65,
	0xb0, 0xff, 0xbc, 0xc5, 0x87, 0x90, 0x76, 0x36, 0x5e, 0x62, 0xda, 0x59, 0xf1, 0x12, 0x9e, 0x74,
	0xbe, 0x0a, 0x61, 0x35, 0xea, 0x01, 0x2b, 0x8f, 0xee, 0x84, 0x8e, 0x79, 0xb6, 0x4a, 0x74, 0xfe,
	0x0d, 0x67, 0xef, 0xf5, 0x80, 0x1f, 0x38, 0xa9, 0x37, 0xfc, 0x5b, 0xdc, 0xfe, 0x0a, 0x00, 0x00,
	0xff, 0xff, 0x2a, 0xe0, 0x6d, 0x45, 0x24, 0x03, 0x00, 0x00,
}
