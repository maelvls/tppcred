package main

import (
	"fmt"
	"strconv"
)

// Error codes and their descriptions. From:
// https://docs.venafi.com/Docs/24.3API/#?route=post-/vedsdk/Credentials/retrieve
type Result int

const (
	ResultSuccess                                   Result = 1
	ResultInvalidArgument                           Result = 2
	ResultInvalidArgumentRange                      Result = 3
	ResultMismatchedArguments                       Result = 4
	ResultNotImplemented                            Result = 5
	ResultInvalidDestinationList                    Result = 6
	ResultInsufficientPrivileges                    Result = 7
	ResultInvalidOperation                          Result = 8
	ResultUnexpectedAssemblyError                   Result = 9
	ResultInvalidNullArgument                       Result = 10
	ResultFailedToObtainConfig                      Result = 11
	ResultFailedToObtainSecretStore                 Result = 12
	ResultInvalidContainerPath                      Result = 13
	ResultRemoteError                               Result = 14
	ResultAttributeDoesNotExist                     Result = 100
	ResultAttributeAlreadyExists                    Result = 101
	ResultAttributeNotFound                         Result = 102
	ResultAttributeValueExists                      Result = 103
	ResultAttributeStillInUse                       Result = 104
	ResultAttributeNameTooLong                      Result = 105
	ResultAttributeReferenceDoesNotExist            Result = 106
	ResultAttributeSyntaxCollision                  Result = 107
	ResultAttributePropertyCollision                Result = 108
	ResultCannotRemoveMandatory                     Result = 109
	ResultAttributeValueIsMandatory                 Result = 110
	ResultAttributeValueTooLong                     Result = 111
	ResultIllegalAttributeForClass                  Result = 112
	ResultInvalidAttributeDN                        Result = 113
	ResultAttributeValueDoesNotExist                Result = 114
	ResultAttributeIsSingleValued                   Result = 115
	ResultAttributeIsReadOnly                       Result = 116
	ResultAttributeIsHidden                         Result = 117
	ResultClassDoesNotExist                         Result = 200
	ResultClassAlreadyExists                        Result = 201
	ResultClassStillInUse                           Result = 202
	ResultClassNameTooLong                          Result = 203
	ResultClassInvalidSuperClass                    Result = 204
	ResultClassInvalidContainmentClass              Result = 205
	ResultClassInvalidNamingAttribute               Result = 206
	ResultClassInvalidMandatoryAttribute            Result = 207
	ResultClassInvalidOptionalAttribute             Result = 208
	ResultClassInvalidName                          Result = 209
	ResultClassInvalidContainmentSubClass           Result = 210
	ResultClassInvalidStructure                     Result = 211
	ResultPolicyDoesNotExist                        Result = 300
	ResultPolicyLockStateCollision                  Result = 301
	ResultLockNameAlreadyExists                     Result = 350
	ResultLockNameDoesNotExist                      Result = 351
	ResultLockNameOwnedByAnother                    Result = 352
	ResultLockNameLimitReached                      Result = 353
	ResultLockNameAttemptTimedOut                   Result = 354
	ResultObjectDoesNotExist                        Result = 400
	ResultObjectAlreadyExists                       Result = 401
	ResultObjectHasChildren                         Result = 402
	ResultObjectNameTooLong                         Result = 403
	ResultObjectDepthTooDeep                        Result = 404
	ResultObjectInvalidName                         Result = 405
	ResultObjectInvalidClass                        Result = 406
	ResultObjectInvalidContainment                  Result = 407
	ResultObjectMandatoryMissing                    Result = 408
	ResultObjectIsReadOnly                          Result = 409
	ResultObjectInvalidOperation                    Result = 410
	ResultDriverMissingDSN                          Result = 500
	ResultDriverMissingDatabaseName                 Result = 501
	ResultDriverDatabaseError                       Result = 502
	ResultDriverTransactionError                    Result = 503
	ResultDriverTransactionCollision                Result = 504
	ResultDriverGenerationUpdateError               Result = 505
	ResultCacheLockException                        Result = 600
	ResultCacheEntryNotFound                        Result = 601
	ResultCacheEntryAlreadyExists                   Result = 602
	ResultCacheEntryIsSuperior                      Result = 603
	ResultCacheEntryIsIncompatible                  Result = 604
	ResultXmlInvalidStructure                       Result = 700
	ResultXmlMissingNaming                          Result = 701
	ResultXmlMissingSyntax                          Result = 702
	ResultXmlMissingProperty                        Result = 703
	ResultXmlUnknownElementAttribute                Result = 704
	ResultAdaptableCredentialNotSupportedType       Result = 800
	ResultAdaptableCredentialScriptHashMismatch     Result = 801
	ResultAdaptableCredentialScriptError            Result = 802
	ResultAdaptableCredentialInvalidConnectorData   Result = 803
	ResultAdaptableCredentialUnexpectedScriptResult Result = 804
	ResultSecretStoreFailed                         Result = 1000
	ResultAddAttributeFailed                        Result = 1001
	ResultUnexpectedException                       Result = 1002
	ResultPartialDeleteFailure                      Result = 1003
	ResultCredentialTypeMismatch                    Result = 1004
	ResultNoDriver                                  Result = 1005
	ResultVaultTypeMismatch                         Result = 1006
	ResultDriverDenied                              Result = 1007
	ResultVaultDataUnrecognized                     Result = 1008
	ResultKeyStoreFailed                            Result = 1009
	ResultCredentialIsInRecycleBin                  Result = 1010
)

// Map error codes to descriptions
type details struct {
	label, description string
}

var errorDescriptions = map[Result]struct{ label, description string }{
	ResultSuccess:                                   details{"Success", "Operation completed successfully."},
	ResultInvalidArgument:                           details{"InvalidArgument", "An invalid method argument was passed to a method."},
	ResultInvalidArgumentRange:                      details{"InvalidArgumentRange", "An argument value is not within the range accepted by a method."},
	ResultMismatchedArguments:                       details{"MismatchedArguments", "One, or more, method argument counts do not match."},
	ResultNotImplemented:                            details{"NotImplemented", "The method has not been implemented."},
	ResultInvalidDestinationList:                    details{"InvalidDestinationList", "A method output argument list is invalid."},
	ResultInsufficientPrivileges:                    details{"InsufficientPrivileges", "The method call has insufficient permissions to perform an operation."},
	ResultInvalidOperation:                          details{"InvalidOperation", "A method call has been attempted using an invalid or disposed instantiated Config object."},
	ResultUnexpectedAssemblyError:                   details{"UnexpectedAssemblyError", "An unexpected error occurred within a called assembly."},
	ResultInvalidNullArgument:                       details{"InvalidNullArgument", "A null argument was passed to a method that does not allow null."},
	ResultFailedToObtainConfig:                      details{"FailedToObtainConfig", "Could not get a config handle."},
	ResultFailedToObtainSecretStore:                 details{"FailedToObtainSecretStore", "Could not get a secret store handle."},
	ResultInvalidContainerPath:                      details{"InvalidContainerPath", "The provided container path does not start at the credentials root."},
	ResultRemoteError:                               details{"RemoteError", "A remote request failed; see Error property for details."},
	ResultAttributeDoesNotExist:                     details{"AttributeDoesNotExist", "The request attribute does not exist."},
	ResultAttributeAlreadyExists:                    details{"AttributeAlreadyExists", "The attribute name already exists within the attribute schema."},
	ResultAttributeNotFound:                         details{"AttributeNotFound", "The attribute was not found within the schema or does not have a value for an object."},
	ResultAttributeValueExists:                      details{"AttributeValueExists", "A matching attribute value already exists for an object."},
	ResultAttributeStillInUse:                       details{"AttributeStillInUse", "The attribute cannot be removed as it is still in use."},
	ResultAttributeNameTooLong:                      details{"AttributeNameTooLong", "The attribute name exceeds the maximum defined length."},
	ResultAttributeReferenceDoesNotExist:            details{"AttributeReferenceDoesNotExist", "The attribute reference cannot be added as it does not exist."},
	ResultAttributeSyntaxCollision:                  details{"AttributeSyntaxCollision", "An attribute exists with a different syntax in the schema."},
	ResultAttributePropertyCollision:                details{"AttributePropertyCollision", "Conflicting attribute properties prevent schema creation."},
	ResultCannotRemoveMandatory:                     details{"CannotRemoveMandatory", "Mandatory attributes cannot be removed."},
	ResultAttributeValueIsMandatory:                 details{"AttributeValueIsMandatory", "Mandatory attribute value not set for object creation."},
	ResultAttributeValueTooLong:                     details{"AttributeValueTooLong", "Attribute value exceeds the maximum length."},
	ResultIllegalAttributeForClass:                  details{"IllegalAttributeForClass", "Attribute not defined as mandatory or optional for schema class."},
	ResultInvalidAttributeDN:                        details{"InvalidAttributeDN", "Object distinguished name in the attribute does not exist."},
	ResultAttributeValueDoesNotExist:                details{"AttributeValueDoesNotExist", "Attribute value not found on the object."},
	ResultAttributeIsSingleValued:                   details{"AttributeIsSingleValued", "Attribute already has a value and is single-valued."},
	ResultAttributeIsReadOnly:                       details{"AttributeIsReadOnly", "Cannot write to a read-only attribute."},
	ResultAttributeIsHidden:                         details{"AttributeIsHidden", "Cannot write to a hidden attribute."},
	ResultClassDoesNotExist:                         details{"ClassDoesNotExist", "No matching schema class definition exists."},
	ResultClassAlreadyExists:                        details{"ClassAlreadyExists", "A schema class definition already exists with that name."},
	ResultClassStillInUse:                           details{"ClassStillInUse", "Schema class definition cannot be removed due to existing objects."},
	ResultClassNameTooLong:                          details{"ClassNameTooLong", "Class name exceeds the maximum length."},
	ResultClassInvalidSuperClass:                    details{"ClassInvalidSuperClass", "One or more super-classes do not exist."},
	ResultClassInvalidContainmentClass:              details{"ClassInvalidContainmentClass", "Contained-by classes do not exist."},
	ResultClassInvalidNamingAttribute:               details{"ClassInvalidNamingAttribute", "Naming attributes are not defined in schema attribute definitions."},
	ResultClassInvalidMandatoryAttribute:            details{"ClassInvalidMandatoryAttribute", "Mandatory attributes are not defined in schema attribute definitions."},
	ResultClassInvalidOptionalAttribute:             details{"ClassInvalidOptionalAttribute", "Optional attributes are not defined in schema attribute definitions."},
	ResultClassInvalidName:                          details{"ClassInvalidName", "Class name is empty."},
	ResultClassInvalidContainmentSubClass:           details{"ClassInvalidContainmentSubClass", "Contained-by super-classes do not exist."},
	ResultClassInvalidStructure:                     details{"ClassInvalidStructure", "Invalid class or attribute relations prevent schema loading."},
	ResultPolicyDoesNotExist:                        details{"PolicyDoesNotExist", "No matching policy found for class and attribute combination."},
	ResultPolicyLockStateCollision:                  details{"PolicyLockStateCollision", "Existing policy lock state does not match the policy being added."},
	ResultLockNameAlreadyExists:                     details{"LockNameAlreadyExists", "Lock name already exists."},
	ResultLockNameDoesNotExist:                      details{"LockNameDoesNotExist", "Specified name is not locked."},
	ResultLockNameOwnedByAnother:                    details{"LockNameOwnedByAnother", "Name is locked by another owner."},
	ResultLockNameLimitReached:                      details{"LockNameLimitReached", "Concurrent lock limit reached."},
	ResultLockNameAttemptTimedOut:                   details{"LockNameAttemptTimedOut", "Lock attempt timed out."},
	ResultObjectDoesNotExist:                        details{"ObjectDoesNotExist", "Specified object does not exist."},
	ResultObjectAlreadyExists:                       details{"ObjectAlreadyExists", "An object with a matching name already exists."},
	ResultObjectHasChildren:                         details{"ObjectHasChildren", "Object cannot be deleted due to existing children."},
	ResultObjectNameTooLong:                         details{"ObjectNameTooLong", "Object name exceeds the maximum permitted length."},
	ResultObjectDepthTooDeep:                        details{"ObjectDepthTooDeep", "Object hierarchical depth exceeds maximum limit."},
	ResultObjectInvalidName:                         details{"ObjectInvalidName", "Object name is empty."},
	ResultObjectInvalidClass:                        details{"ObjectInvalidClass", "Schema class definition not found."},
	ResultObjectInvalidContainment:                  details{"ObjectInvalidContainment", "Parent schema class not defined as contained-by class."},
	ResultObjectMandatoryMissing:                    details{"ObjectMandatoryMissing", "Mandatory attributes for the object are missing."},
	ResultObjectIsReadOnly:                          details{"ObjectIsReadOnly", "Object cannot be modified."},
	ResultObjectInvalidOperation:                    details{"ObjectInvalidOperation", "Operation not allowed on the object."},
	ResultDriverMissingDSN:                          details{"DriverMissingDSN", "No database connection information found."},
	ResultDriverMissingDatabaseName:                 details{"DriverMissingDatabaseName", "Database name not defined in connection information."},
	ResultDriverDatabaseError:                       details{"DriverDatabaseError", "Error occurred between storage driver and database."},
	ResultDriverTransactionError:                    details{"DriverTransactionError", "Transaction error during a write operation."},
	ResultDriverTransactionCollision:                details{"DriverTransactionCollision", "Write operation collision in progress."},
	ResultDriverGenerationUpdateError:               details{"DriverGenerationUpdateError", "Failed to update storage driver schema generation."},
	ResultCacheLockException:                        details{"CacheLockException", "Schema cache lock management error."},
	ResultCacheEntryNotFound:                        details{"CacheEntryNotFound", "No matching entry name in schema cache."},
	ResultCacheEntryAlreadyExists:                   details{"CacheEntryAlreadyExists", "Entry with matching name already exists in schema cache."},
	ResultCacheEntryIsSuperior:                      details{"CacheEntryIsSuperior", "Entry with matching name and additional definitions exists."},
	ResultCacheEntryIsIncompatible:                  details{"CacheEntryIsIncompatible", "Conflicting definitions prevent adding entry to cache."},
	ResultXmlInvalidStructure:                       details{"XmlInvalidStructure", "XML document structure is invalid."},
	ResultXmlMissingNaming:                          details{"XmlMissingNaming", "XML element is missing the name attribute."},
	ResultXmlMissingSyntax:                          details{"XmlMissingSyntax", "XML element is missing the syntax attribute."},
	ResultXmlMissingProperty:                        details{"XmlMissingProperty", "XML element is missing the property attribute."},
	ResultXmlUnknownElementAttribute:                details{"XmlUnknownElementAttribute", "XML element has an unknown attribute."},
	ResultAdaptableCredentialNotSupportedType:       details{"AdaptableCredentialNotSupportedType", "Credential type is not supported."},
	ResultAdaptableCredentialScriptHashMismatch:     details{"AdaptableCredentialScriptHashMismatch", "PowerShell script is modified."},
	ResultAdaptableCredentialScriptError:            details{"AdaptableCredentialScriptError", "PowerShell script returned an error."},
	ResultAdaptableCredentialInvalidConnectorData:   details{"AdaptableCredentialInvalidConnectorData", "Adaptable Connector data is invalid."},
	ResultAdaptableCredentialUnexpectedScriptResult: details{"AdaptableCredentialUnexpectedScriptResult", "Unexpected result returned by PowerShell script."},
	ResultSecretStoreFailed:                         details{"SecretStoreFailed", "Credential data could not be stored in secret store."},
	ResultAddAttributeFailed:                        details{"AddAttributeFailed", "Attributes could not be added to vault object."},
	ResultUnexpectedException:                       details{"UnexpectedException", "Encountered an unhandled exception."},
	ResultPartialDeleteFailure:                      details{"PartialDeleteFailure", "Problem deleting an object in recursive delete; partial delete may have occurred."},
	ResultCredentialTypeMismatch:                    details{"CredentialTypeMismatch", "Tried to update a credential with a different type."},
	ResultNoDriver:                                  details{"NoDriver", "Could not find a driver for the credential object."},
	ResultVaultTypeMismatch:                         details{"VaultTypeMismatch", "Vault secret type does not match the credential."},
	ResultDriverDenied:                              details{"DriverDenied", "Credential driver denied renaming the credential."},
	ResultVaultDataUnrecognized:                     details{"VaultDataUnrecognized", "Vault data is not in a supported format."},
	ResultKeyStoreFailed:                            details{"KeyStoreFailed", "Credential failed to be stored in the KeyStore."},
	ResultCredentialIsInRecycleBin:                  details{"CredentialIsInRecycleBin", "Credential is in the recycle bin and must be purged before reimporting."},
}

// ResultString returns the description of the error code. Example:
//
//	"400 ObjectDoesNotExist: Specified object does not exist."
func ResultString(result Result) string {
	if desc, ok := errorDescriptions[Result(result)]; ok {
		return strconv.Itoa(int(result)) + " " + desc.label + ": " + desc.description
	}
	return fmt.Sprintf("Unknown error code: %d", result)
}

func ResultCode(result Result) string {
	if desc, ok := errorDescriptions[result]; ok {
		return desc.label
	}
	return "Unknown error code"
}

