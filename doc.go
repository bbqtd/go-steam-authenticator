/*
Package authenticator implements behavior of Steam Guard Mobile Authenticator
for generating authentication and confirmation codes.

Depended on the code that you want generate you must provide shared secret or
identity secret encoded in base64. It looks like this:

	AaIgne2cvI6eu991XVfJOsanEAo=

If you need generate code only once then you will like it group of GenerateXXX functions.
Otherwise Authenticator is preferable.
*/
package authenticator
