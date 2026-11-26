// Icono de Sentinel en la barra de menú de macOS: un escudo del color del estado, con acceso al panel.
// Corre con tu usuario y solo lee («sentinel resumen»). Lo compila el instalador.
import Cocoa

let sentinel = ProcessInfo.processInfo.environment["SENTINEL_BIN"] ?? "/usr/local/bin/sentinel"
let niveles: [String: (texto: String, color: NSColor)] = [
    "protegido": ("Protegido", .systemGreen), "revision": ("Para revisar", .systemYellow),
    "atencion": ("Requiere atención", .systemOrange), "peligro": ("Posible intrusión", .systemRed),
]

func leerEstado() -> (nivel: String, detalle: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: sentinel)
    p.arguments = ["resumen", "--json"]
    let salida = Pipe()
    p.standardOutput = salida
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return ("desconocido", "No pude ejecutar Sentinel") }
    let datos = salida.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    guard let j = (try? JSONSerialization.jsonObject(with: datos)) as? [String: Any], let nivel = j["level"] as? String
    else { return ("desconocido", "Sin datos") }
    return (nivel, j["why"] as? String ?? "")
}

func titulo(_ nivel: String) -> String { niveles[nivel]?.texto ?? "Sin datos" }

if CommandLine.arguments.contains("--una-vez") {  // para probarlo sin pantalla
    let e = leerEstado()
    print("\(e.nivel)|\(titulo(e.nivel))|\(e.detalle)")
    exit(0)
}

final class Barra: NSObject, NSApplicationDelegate {
    var item: NSStatusItem!

    func applicationDidFinishLaunching(_ aviso: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        pintar("desconocido", "Consultando…")
        actualizar()
        Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in self?.actualizar() }
    }

    @objc func actualizar() {
        DispatchQueue.global().async {
            let e = leerEstado()
            DispatchQueue.main.async { self.pintar(e.nivel, e.detalle) }
        }
    }

    func pintar(_ nivel: String, _ detalle: String) {
        let icono = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "Sentinel: \(titulo(nivel))")
        icono?.isTemplate = true
        item.button?.image = icono
        item.button?.contentTintColor = niveles[nivel]?.color ?? .systemGray
        item.button?.toolTip = "Sentinel · \(titulo(nivel))"
        let menu = NSMenu()
        menu.addItem(withTitle: "Sentinel · \(titulo(nivel))", action: nil, keyEquivalent: "")
        if !detalle.isEmpty { menu.addItem(withTitle: String(detalle.prefix(90)), action: nil, keyEquivalent: "") }
        menu.addItem(.separator())
        menu.addItem(withTitle: "Abrir panel", action: #selector(abrir), keyEquivalent: "").target = self
        menu.addItem(withTitle: "Consultar ahora", action: #selector(actualizar), keyEquivalent: "").target = self
        menu.addItem(withTitle: "Quitar el icono", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "")
        item.menu = menu
    }

    @objc func abrir() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-a", "Sentinel"]
        try? p.run()
    }
}

let app = NSApplication.shared
let barra = Barra()
app.delegate = barra
app.setActivationPolicy(.accessory)
app.run()
