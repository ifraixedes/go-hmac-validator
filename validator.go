package hmacval

/*

Process to validate an HMAC digest signature:

Take request URL query parameters and body (I'll call it 'payload' onwards)
 1. Exclude keys which shouldn't be considered to perform the HMAC signature
 2. If HMAC digest is inside of the payload then extract it and exclude it from the HMAC signature
 1. Performs character replacement on the payload keys, values or both
 2. Join the payload Keys and its values with a specified string or none
 3. Join the payload Keys/values pairs with a specific string or none
 4. Compute the digest on the payload with the specified secret and required encoding
 5. Compare the resulted digest with the provided one (in the payload or aside) and returns if it matches or not.
*/
