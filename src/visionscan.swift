import Foundation
import Vision
import CoreImage
import AppKit

struct Box: Codable { let x: Double; let y: Double; let w: Double; let h: Double; let c: Double }
struct TextItem: Codable { let text: String; let box: Box }
struct Quad: Codable { let corners: [[Double]]; let conf: Double }

struct Output: Codable {
    var width = 0
    var height = 0
    var text: [TextItem] = []
    var faces: [Box] = []
    var humans: [Box] = []
    var personCoverage = 0.0
    var personBBox: Box? = nil
    var docQuad: Quad? = nil
    var errors: [String] = []
}

func toPixels(_ bb: CGRect, _ w: Int, _ h: Int, _ conf: Double) -> Box {
    Box(x: bb.minX * Double(w),
        y: (1.0 - bb.maxY) * Double(h),
        w: bb.width * Double(w),
        h: bb.height * Double(h),
        c: conf)
}

guard CommandLine.arguments.count > 1 else {
    FileHandle.standardError.write("usage: visionscan <image>\n".data(using: .utf8)!)
    exit(64)
}
let path = CommandLine.arguments[1]

guard let nsImage = NSImage(contentsOfFile: path),
      let cgImage = nsImage.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    FileHandle.standardError.write("cannot decode image\n".data(using: .utf8)!)
    exit(65)
}

var out = Output()
out.width = cgImage.width
out.height = cgImage.height
let W = out.width, H = out.height

let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])

// --- OCR, word-level boxes -------------------------------------------------
let textReq = VNRecognizeTextRequest()
textReq.recognitionLevel = .accurate
textReq.usesLanguageCorrection = false

// --- faces -----------------------------------------------------------------
let faceReq = VNDetectFaceRectanglesRequest()

// --- whole humans ----------------------------------------------------------
let humanReq = VNDetectHumanRectanglesRequest()
humanReq.upperBodyOnly = false

// --- person segmentation (catches parts a box detector misses) -------------
let segReq = VNGeneratePersonSegmentationRequest()
segReq.qualityLevel = .balanced
segReq.outputPixelFormat = kCVPixelFormatType_OneComponent8

// --- board / document quad -------------------------------------------------
let docReq = VNDetectDocumentSegmentationRequest()

do {
    try handler.perform([textReq, faceReq, humanReq, segReq, docReq])
} catch {
    out.errors.append("perform: \(error.localizedDescription)")
}

for obs in (textReq.results ?? []) {
    guard let cand = obs.topCandidates(1).first else { continue }
    let s = cand.string
    var idx = s.startIndex
    while idx < s.endIndex {
        if s[idx] == " " { idx = s.index(after: idx); continue }
        var end = idx
        while end < s.endIndex && s[end] != " " { end = s.index(after: end) }
        let range = idx..<end
        if let wordBox = try? cand.boundingBox(for: range) {
            out.text.append(TextItem(text: String(s[range]),
                                     box: toPixels(wordBox.boundingBox, W, H, Double(obs.confidence))))
        }
        idx = end
    }
}

for obs in (faceReq.results ?? []) {
    out.faces.append(toPixels(obs.boundingBox, W, H, Double(obs.confidence)))
}

for obs in (humanReq.results ?? []) {
    out.humans.append(toPixels(obs.boundingBox, W, H, Double(obs.confidence)))
}

if let seg = segReq.results?.first {
    let pb = seg.pixelBuffer
    CVPixelBufferLockBaseAddress(pb, .readOnly)
    let mw = CVPixelBufferGetWidth(pb), mh = CVPixelBufferGetHeight(pb)
    let stride = CVPixelBufferGetBytesPerRow(pb)
    if let base = CVPixelBufferGetBaseAddress(pb) {
        let p = base.assumingMemoryBound(to: UInt8.self)
        var hits = 0
        var minX = mw, minY = mh, maxX = -1, maxY = -1
        for row in 0..<mh {
            for col in 0..<mw where p[row * stride + col] > 128 {
                hits += 1
                if col < minX { minX = col }
                if col > maxX { maxX = col }
                if row < minY { minY = row }
                if row > maxY { maxY = row }
            }
        }
        out.personCoverage = mw * mh > 0 ? Double(hits) / Double(mw * mh) : 0
        // The mask catches limbs and edges a box detector clips, so its extent
        // is what must be painted, not just the human rectangle.
        if maxX >= 0 && mw > 0 && mh > 0 {
            let sx = Double(W) / Double(mw), sy = Double(H) / Double(mh)
            out.personBBox = Box(x: Double(minX) * sx, y: Double(minY) * sy,
                                 w: Double(maxX - minX + 1) * sx,
                                 h: Double(maxY - minY + 1) * sy, c: 1.0)
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, .readOnly)
}

if let doc = docReq.results?.first {
    out.docQuad = Quad(corners: [
        [doc.topLeft.x * Double(W),     (1 - doc.topLeft.y) * Double(H)],
        [doc.topRight.x * Double(W),    (1 - doc.topRight.y) * Double(H)],
        [doc.bottomRight.x * Double(W), (1 - doc.bottomRight.y) * Double(H)],
        [doc.bottomLeft.x * Double(W),  (1 - doc.bottomLeft.y) * Double(H)],
    ], conf: Double(doc.confidence))
}

let enc = JSONEncoder()
FileHandle.standardOutput.write(try! enc.encode(out))
