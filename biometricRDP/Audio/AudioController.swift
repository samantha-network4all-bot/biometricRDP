import AppKit

final class AudioController: NSViewController, TestAPIControllerRoutes {
    static var routePrefix: String { "audio" }

    weak var sessionController: SessionController?

    /// Whether audio channel is active (received SNDC_FORMATS).
    private var audioActive: Bool = false

    /// Audio format description.
    private var audioFormat: String = ""

    /// Total PCM samples received from the remote.
    private var samplesReceived: Int = 0

    private var isTestMode: Bool {
        ProcessInfo.processInfo.environment["BIOMETRICRDP_TEST_API"] == "1"
    }

    init(sessionController: SessionController) {
        self.sessionController = sessionController
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func loadView() { view = NSView(frame: .zero) }

    override func viewDidLoad() {
        super.viewDidLoad()
        TestAPIRouter.shared.register(controller: self)
    }

    func handleAudioChannelData(_ data: Data) {
        guard let msg = RDPSND.parseMessage(data) else { return }
        switch msg.msgType {
        case RDPSND.SNDC_FORMATS:
            audioActive = true
            audioFormat = "pcm_s16le_44100"
        case RDPSND.SNDC_WAVE:
            // PCM data in the wave body: each sample is 2 bytes (16-bit),
            // stereo = 2 channels, so 4 bytes per frame.
            // Count total samples (frames * channels).
            let pcmBytes = msg.body.count
            samplesReceived += pcmBytes / 2 // 16-bit = 2 bytes per sample
        case RDPSND.SNDC_TRAINING:
            break
        case RDPSND.SNDC_CLOSE:
            audioActive = false
        default:
            break
        }
    }

    func registerRoutes(on router: TestAPIRouter) {
        // GET /audio/state → {active, format, samplesReceived}
        router.get(prefix: Self.routePrefix, path: "/state") { [weak self] _ in
            guard let self else { return .notFound }
            let resp: [String: Any] = [
                "active": self.audioActive,
                "format": self.audioFormat,
                "samplesReceived": self.samplesReceived
            ]
            guard let data = try? JSONSerialization.data(withJSONObject: resp) else {
                return .internalError
            }
            return .ok(json: data)
        }
    }
}
