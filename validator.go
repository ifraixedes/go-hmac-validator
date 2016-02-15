package hmacval

/*

Process to validate an HMAC digest signature:

Take map with string type keys and values (I'll call it 'payload' onwards)
 1. If HMAC digest is inside of the payload then extract it and exclude it from the HMAC signature
 2. Exclude keys which shouldn't be considered to perform the HMAC signature
 3. Performs character replacement on the payload keys, values or both
 4. Sort the payload key/values lexicographically
 5. Join the payload Keys and its values with a specified string or none
 6. Join the payload Keys/values pairs with a specific string or none
 7. Compute the digest on the payload with the specified secret and required encoding
 8. Compare the resulted digest with the provided one (in the payload or aside) and returns if it matches or not.
*/
