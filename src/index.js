import { readFile } from "fs/promises"
import { X509Certificate, createHash, createVerify } from "crypto"

function cultureInvariantFloat(num) {
	const roundedValue = Math.round(+num * 100) / 100 // Round to 2 decimal places
	// Convert to string and remove second trailing zero if present
	const stringValue = Number.isInteger(roundedValue * 10)
		? roundedValue.toFixed(1)
		: roundedValue.toFixed(2)
	return stringValue
}

function getMessage(validation) {
	return `${validation.ValidationRequestId}${validation.Approved}${validation.ReasonNotApproved || ""}${validation.ReasonNotApprovedCode}${cultureInvariantFloat(validation.TotalValue)}${cultureInvariantFloat(validation.TotalVat)}`
}

export default async function verifySignature({ path }) {
	// read a text file
	const fileContents = await readFile(path, { encoding: "utf8" })
	// deserialize text into an object
	const request = JSON.parse(fileContents)
	// convert from base64 text into a public key
	const publicKeyBuffer = Buffer.from(request.PublicKey, "base64")
	// create a X509 certificate from public key
	const certificate = new X509Certificate(publicKeyBuffer)
	// should get the RSA public key from the certificate
	const rsaPublicKey = certificate.publicKey
	const verifyResults = []
	for (let validationResult of request.ValidationResults) {
		// convert from base64 text the signature of proof
		const signatureBuffer = Buffer.from(validationResult.SignatureOfProof, "base64")
		// should compose a canonical message from a ValidationResult object
		const message = getMessage(validationResult)
		// should convert a canonical message into utf8 byte array
		const messageBytes = Buffer.from(message, "utf8")
		// should create a hash of the message using SHA512 and Pkcs1 padding
		const hash = createHash("SHA512").update(messageBytes).digest()
		// should verify the validity of the signature
		const verify = createVerify("SHA512").update(messageBytes)
		const isValid = verify.verify(rsaPublicKey, signatureBuffer)
		verifyResults.push({
			signatureBuffer,
			message,
			messageBytes,
			hash,
			isValid,
			id: validationResult.ValidationRequestId,
		})
	}
	return {
		fileContents,
		request,
		publicKeyBuffer,
		certificate,
		rsaPublicKey,
		verifyResults,
	}
}

function logSummary({ verifyResults }) {
	verifyResults.forEach(
		({ id, isValid }) =>
			process.env.npm_lifecycle_event !== "test" &&
			console.log(`-- Signature of result ${id} is ${isValid ? "valid" : "invalid"}`)
	)
}

async function main() {
	logSummary(
		await verifySignature({
			path: "assets/IN-CU005/request.json",
		})
	)
	logSummary(
		await verifySignature({
			path: "assets/IN-CU006/request.json",
		})
	)
	logSummary(
		await verifySignature({
			path: "assets/IN-CU007/request.json",
		})
	)
	logSummary(
		await verifySignature({
			path: "assets/IN-CU008/request.json",
		})
	)
}

main()
