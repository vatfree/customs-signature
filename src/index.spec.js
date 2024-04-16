import { expect } from "chai"
import validateScenario from "./index.js"
import { X509Certificate } from "crypto"

function makeScenarioTest({
	path,
	fileContentsContain,
	publicKeyContain,
	publicKeyBufferLength,
	certificateIssuerLines,
	validationResultIndex,
	message,
	messageBytesLength,
	messageHashLength,
	isValid,
}) {
	return async function () {
		it("read a text file", async function () {
			const { fileContents } = await validateScenario({
				path,
			})
			expect(fileContents).to.be.a("string")
			expect(fileContents).to.contain(fileContentsContain)
		})
		it("deserialize text into an object", async function () {
			const { request } = await validateScenario({
				path,
			})
			expect(request).to.be.an("object")
			expect(request.PublicKey).to.contain(publicKeyContain)
		})
		it("convert from base64 text into a public key buffer", async function () {
			const { publicKeyBuffer } = await validateScenario({
				path,
			})
			expect(publicKeyBuffer).to.be.instanceOf(Buffer)
			expect(publicKeyBuffer.length).to.equal(publicKeyBufferLength)
		})
		it("create a X509 certificate from public key", async function () {
			const { certificate } = await validateScenario({
				path,
			})
			expect(certificate).to.be.instanceOf(X509Certificate)
			certificateIssuerLines.forEach((line) => {
				expect(certificate.issuer).to.contain(line)
			})
		})
		it("should get the RSA public key from the certificate", async function () {
			const { rsaPublicKey } = await validateScenario({
				path,
			})
			expect(rsaPublicKey.asymmetricKeyType).to.equal("rsa")
		})
		it("convert from base64 text the signature of proof", async function () {
			const { verifyResults } = await validateScenario({
				path,
			})
			expect(verifyResults).to.be.an("array")
			expect(verifyResults[validationResultIndex].signatureBuffer).to.be.instanceOf(Buffer)
		})
		it("should compose a canonical message from a ValidationResult object", async function () {
			const { verifyResults } = await validateScenario({
				path,
			})
			expect(verifyResults[validationResultIndex].message).to.be.a("string")
			expect(verifyResults[validationResultIndex].message).to.equal(message)
		})
		it("should convert a canonical message into utf8 byte array", async function () {
			const { verifyResults } = await validateScenario({
				path,
			})
			expect(verifyResults[validationResultIndex].messageBytes).to.be.instanceOf(Buffer)
			expect(verifyResults[validationResultIndex].messageBytes.length).to.equal(
				messageBytesLength
			)
		})
		it("should create a hash of the message using SHA512 and Pkcs1 padding", async function () {
			const { verifyResults } = await validateScenario({
				path,
			})
			expect(verifyResults[validationResultIndex].hash).to.be.instanceOf(Buffer)
			expect(verifyResults[validationResultIndex].hash.length).to.equal(messageHashLength)
		})
		it("should verify the validity of the signature", async function () {
			const { verifyResults } = await validateScenario({
				path,
			})
			expect(verifyResults[validationResultIndex].isValid).to.equal(isValid)
		})
	}
}

const certificateChecks = {
	publicKeyContain:
		"MIIKLjCCCBagAwIBAgIUWm0NVfo+bwxE7ci2ff0WJy5/6vcwDQYJKoZIhvcNAQELBQAwXTELMAkGA1UEBhMC",
	publicKeyBufferLength: 2610,
	certificateIssuerLines: [
		"C=NL",
		"CN=QuoVadis PKIoverheid Server CA 2020",
		"O=QuoVadis Trustlink B.V.",
	],
}

describe("validate scenario", function () {
	describe(
		"IN-CU005, result 0",
		makeScenarioTest({
			path: "assets/IN-CU005/request.json",
			validationResultIndex: 0,
			fileContentsContain: "N000680W00008200003000009071",
			...certificateChecks,
			message: "N000680W00008200003000009071ApprovedNone0300.0052.07",
			messageBytesLength: 52,
			messageHashLength: 64,
			isValid: true,
		})
	)

	describe(
		"IN-CU005, result 1",
		makeScenarioTest({
			path: "assets/IN-CU005/request.json",
			validationResultIndex: 1,
			fileContentsContain: "N000680W00008200003000009071",
			...certificateChecks,
			message: "N000680W00008300005000009071ApprovedNone0500.0086.78",
			messageBytesLength: 52,
			messageHashLength: 64,
			isValid: true,
		})
	)

	describe(
		"IN-CU006, result 0",
		makeScenarioTest({
			path: "assets/IN-CU006/request.json",
			validationResultIndex: 0,
			fileContentsContain: "N000680W00004700005000022061",
			...certificateChecks,
			message: "N000680W00004700005000022061Approved0500.062.5",
			messageBytesLength: 46,
			messageHashLength: 64,
			isValid: true,
		})
	)

	describe(
		"IN-CU006, result 1",
		makeScenarioTest({
			path: "assets/IN-CU006/request.json",
			validationResultIndex: 1,
			fileContentsContain: "N000680W00004700005000022061",
			...certificateChecks,
			message: "N000680W00004800001000022061Approved0100.011.0",
			messageBytesLength: 46,
			messageHashLength: 64,
			isValid: true,
		})
	)

	describe(
		"IN-CU006, result 2",
		makeScenarioTest({
			path: "assets/IN-CU006/request.json",
			validationResultIndex: 2,
			fileContentsContain: "N000680W00004700005000022061",
			...certificateChecks,
			message: "N000680W00004900001500022061Approved0150.017.25",
			messageBytesLength: 47,
			messageHashLength: 64,
			isValid: true,
		})
	)
	describe(
		"IN-CU007, result 0",
		makeScenarioTest({
			path: "assets/IN-CU007/request.json",
			validationResultIndex: 0,
			fileContentsContain: "N000680W00004100002000022061",
			...certificateChecks,
			message: "N000680W00004100002000022061NotApprovedProduct not shown101200.025.0",
			messageBytesLength: 68,
			messageHashLength: 64,
			isValid: true,
		})
	)
	describe(
		"IN-CU008, result 0",
		makeScenarioTest({
			path: "assets/IN-CU008/request.json",
			validationResultIndex: 0,
			fileContentsContain: "N000680W00004200002000022061",
			...certificateChecks,
			message:
				"N000680W00004200002000022061NotApprovedProductDoesNotMatchInvoice102200.025.0",
			messageBytesLength: 77,
			messageHashLength: 64,
			isValid: true,
		})
	)
})
