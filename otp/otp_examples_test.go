package otp_test

import (
	"fmt"
	"math/rand"

	stc "ibm-security-innovation/libsecurity-go/defs"
	en "ibm-security-innovation/libsecurity-go/entity"
	"ibm-security-innovation/libsecurity-go/otp"
)

const (
	entityName = "Entity1"
)

var (
	entityManager *en.EntityManager
	secret        = []byte("ABCDABCD12341234")
)

func init() {
	entityManager = en.NewEntityManager()
}

func addOtpUser(id string, secret []byte, startCounter int64) {
	entityManager.AddUser(id)
	otpUser, _ := otp.NewOtpUser(secret, false, 10, 1, 100, 2, 0, startCounter)
	entityManager.AddPropertyToEntity(id, stc.OtpPropertyName, otpUser)
}

// The TOTP example demonstrates the following secenario:
// Verify that the calculated TOTP for the current time
// is as expected by the provider
func ExampleTotp() {
	addOtpUser(entityName, secret, 0)

	totp, err := otp.NewTotp(secret)
	if err != nil {
		fmt.Println("TOTP can't be initialized, Error: ", err)
	}
	code, err := totp.Now()
	if err != nil {
		fmt.Println("Can't generate TOTP, error: ", err)
	} else {
		e, _ := entityManager.GetPropertyAttachedToEntity(entityName, stc.OtpPropertyName)
		if e == nil {
			return
		}
		entity, ok := e.(*otp.OtpUser)
		if ok == true {
			ok, err := entity.VerifyOtpUserCode(code, otp.TotpType)
			if ok {
				fmt.Println("TOTP: Entity:", entityName, "Code:", code, "as expected")
			} else {
				fmt.Println("TOTP: Entity:", entityName, "Code:", code, "is not as expected, error:", err)
			}
		}
	}
}

type HotpUser struct {
	name    string
	counter int64
	hotp    *otp.Hotp
}

func (u HotpUser) String() string {
	ret := fmt.Sprintf("Entity id: %v, counter %v", u.name, u.counter)
	return ret
}

func initHotpUserslist(users []HotpUser, secret []byte) {
	for i, user := range users {
		addOtpUser(user.name, secret, user.counter)
		hotp, err := otp.NewHotp(secret, user.counter)
		if err != nil {
			fmt.Println("HOTP can't be initialized, error: ", err)
		}
		users[i].hotp = hotp
	}
}

// The HOTP example demonstrates the following secenarios:
// Adding 2 users, each with a different initial counter and
// Repeat the following 10 times:
//   randomly select one of the users, verify that the calculated HOTP
//   is as expected by the provider and then increase the internal counter
//   of the randomly selected user by one
func ExampleHotp() {
	users := []HotpUser{{name: "camera", counter: 2000}, {name: "cell-phone", counter: 1000}}
	initHotpUserslist(users, secret)

	for i := 0; i < 10; i++ {
		idx := rand.Int() % len(users)
		hotp := users[idx].hotp
		code, err := hotp.Next()
		if err != nil {
			fmt.Println("Can't generate HOTP, error: ", err)
		} else {
			entity, _ := entityManager.GetPropertyAttachedToEntity(users[idx].name, stc.OtpPropertyName)
			if entity != nil {
				ok, err := entity.(*otp.OtpUser).VerifyOtpUserCode(code, otp.HotpType)
				if ok {
					fmt.Printf("HOTP: %v, Code: %v as expected\n", users[idx], code)
					users[idx].counter++
				} else {
					fmt.Printf("HOTP: %v code %v is not as expected, error: %v\n", users[idx], code, err)
				}
			}
		}
	}
}
