package twofactor

import (
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }
type AuthSuite struct {}
type RouteSuite struct {}

var _ = Suite(&AuthSuite{})

func (s *AuthSuite) TestNewAuth(c *C) {
	a, err := NewAuth("something")
	c.Check(err, NotNil)
	a, err = NewAuth("ab7a+5*LcVg")
	c.Check(err, IsNil)
	c.Check(a, NotNil)
	c.Check(a.IsDirty(), Equals, true)
	err = a.CheckPassword("foo")
	c.Check(err, NotNil)
	c.Check(a.Password, Not(Equals), "ab7a+5*LcVg")
	err = a.CheckPassword("ab7a+5*LcVg")
	c.Check(err, IsNil)
}

func (s *AuthSuite) TestReset(c *C) {
	a, err := NewAuth("ab7a+5*LcVg")
	c.Check(err, IsNil)
	err = a.CheckResetCode("blah blah")
	c.Check(err, NotNil)
	code, err := a.ResetPassword(time.Second)
	c.Check(err, IsNil)
	c.Check(a.IsDirty(), Equals, true)
	err = a.CheckResetCode("blah blah")
	c.Check(err, NotNil)
	err = a.CheckResetCode(code)
	c.Check(err, IsNil)
	err = a.CheckResetCode(code)
	c.Check(err, IsNil)
	time.Sleep(2 * time.Second)
	err = a.CheckResetCode(code)
	c.Check(err, NotNil)
}

func (s *AuthSuite) TestInit2FA(c *C) {
	a, err := NewAuth("ab7a+5*LcVg")
	c.Check(err, IsNil)
	_, _, err = a.Configure2FA("rclancey", "github.com")
	c.Check(err, IsNil)
	err = a.Check2FA("1234")
	c.Check(err, IsNil)
	err = a.Complete2FA("1234")
	c.Check(err, NotNil)
	code := a.InitTwoFactor.GenCode()
	err = a.Complete2FA(code)
	c.Check(err, IsNil)
	err = a.Check2FA(code)
	c.Check(err, IsNil)
}
