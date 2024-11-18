package remove
import (
	"fmt"
	"github.com/miekg/pkcs11"
)

// DeleteKeyByAlias deletes a key from the HSM using its alias (label)
func DeleteKeyByAlias(p *pkcs11.Ctx, session pkcs11.SessionHandle, alias string) error {
	// Initialize the search for objects with the given label
	err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, alias),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize object search: %v", err)
	}

	// Retrieve handles for objects matching the alias
	handles, _, err := p.FindObjects(session, 10) // Retrieve up to 10 matchesa
	if err != nil {
		p.FindObjectsFinal(session)
		return fmt.Errorf("failed to find objects: %v", err)
	}

	// Finalize the search
	err = p.FindObjectsFinal(session)
	if err != nil {
		return fmt.Errorf("failed to finalize object search: %v", err)
	}

	// Check if any objects were found with the specified alias
	if len(handles) == 0 {
		return fmt.Errorf("no objects found with alias: %s", alias)
	}

	// Delete each object found with the specified alias
	for _, handle := range handles {
		err = p.DestroyObject(session, handle)
		if err != nil {
			return fmt.Errorf("failed to delete object with alias %s: %v", alias, err)
		}
		fmt.Printf("Successfully deleted object with alias: %s\n", alias)
	}
	return nil
}
