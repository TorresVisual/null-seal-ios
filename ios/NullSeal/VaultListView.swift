import SwiftUI
import UIKit

/// Everyday vault screen: searchable list of logins and notes, with add, detail, edit and delete.
/// Other item types are listed but not opened yet.
struct VaultListView: View {
    @ObservedObject var session: AppSession
    @State private var query = ""
    @State private var adding = false

    private var rows: [ItemRow] {
        guard !query.isEmpty else { return session.items }
        return session.items.filter { r in
            [r.title, r.username, r.url, r.folder, r.tags.joined(separator: " ")]
                .contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }

    var body: some View {
        List {
            if let error = session.error {
                Text(error).foregroundStyle(.red)
            }
            Section {
                ForEach(rows, id: \.id) { row in
                    if row.kind == .other {
                        ItemLabel(row: row).foregroundStyle(.secondary)
                    } else {
                        NavigationLink { ItemDetailView(session: session, row: row) } label: {
                            ItemLabel(row: row)
                        }
                    }
                }
            } header: {
                Text("\(session.items.count) items").accessibilityIdentifier("items")
            }
            Section {
                NavigationLink("Password generator") { GeneratorView() }
                LabeledContent("Core", value: coreVersion())
                if DeviceKey.available {
                    Toggle(
                        "Unlock with Face ID",
                        isOn: Binding(
                            get: { session.faceID },
                            set: { on in
                                if on { Task { await session.enableFaceID() } } else { session.disableFaceID() }
                            }))
                }
                Button("Lock") { session.lock() }
            }
        }
        .searchable(text: $query)
        .refreshable { await session.refresh() }
        .navigationTitle("Null Seal")
        .toolbar {
            Button("Add", systemImage: "plus") { adding = true }
        }
        .sheet(isPresented: $adding) {
            NavigationStack {
                ItemEditView(session: session, id: nil, kind: .login, data: .empty) { _ in adding = false }
            }
        }
    }
}

private struct ItemLabel: View {
    let row: ItemRow

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text(row.title.isEmpty ? "Untitled" : row.title)
                if row.favorite { Image(systemName: "star.fill").foregroundStyle(.yellow) }
            }
            let sub = row.kind == .other ? "Not supported on iOS yet" : row.username
            if !sub.isEmpty { Text(sub).font(.caption).foregroundStyle(.secondary) }
        }
    }
}

struct ItemDetailView: View {
    @ObservedObject var session: AppSession
    let row: ItemRow
    @State private var data: LoginData?
    @State private var reveal = false
    @State private var editing = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            if let d = data {
                if row.kind == .login {
                    field("Username", d.username)
                    Section("Password") {
                        Text(reveal ? d.password : String(repeating: "•", count: d.password.count))
                            .font(.system(.body, design: .monospaced))
                        Button(reveal ? "Hide" : "Show") { reveal.toggle() }
                        Button("Copy") { copy(d.password) }
                    }
                    field("Website", d.url)
                }
                field("Notes", d.notes)
            } else if let e = session.error {
                Text(e).foregroundStyle(.red)
            }
        }
        .navigationTitle(row.title)
        .toolbar { Button("Edit") { editing = true }.disabled(data == nil) }
        .task { await load() }
        .sheet(isPresented: $editing) {
            if let d = data {
                NavigationStack {
                    ItemEditView(session: session, id: row.id, kind: row.kind, data: d) { deleted in
                        editing = false
                        if deleted { dismiss() } else { Task { await load() } }
                    }
                }
            }
        }
    }

    @ViewBuilder private func field(_ label: String, _ value: String) -> some View {
        if !value.isEmpty {
            Section(label) {
                Text(value).textSelection(.enabled)
                Button("Copy") { copy(value) }
            }
        }
    }

    private func load() async {
        data = try? await session.load(row.id)
    }

    /// Local to this device and gone after a minute. Wider clipboard policy is #91.
    private func copy(_ text: String) {
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: text]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
    }
}

/// Create (`id` nil) or edit a login or note; `done(true)` means the item was deleted.
struct ItemEditView: View {
    @ObservedObject var session: AppSession
    let id: String?
    let kind: ItemKind
    @State var data: LoginData
    let done: (_ deleted: Bool) -> Void
    @State private var confirmDelete = false

    var body: some View {
        Form {
            Section { TextField("Title", text: $data.title) }
            if kind == .login {
                Section {
                    TextField("Username", text: $data.username)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("Password", text: $data.password)
                    Button("Generate password") {
                        if let p = try? generatePassword(length: 20) { data.password = p }
                    }
                    TextField("Website", text: $data.url)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                }
            }
            Section("Notes") { TextField("Notes", text: $data.notes, axis: .vertical).lineLimit(3...10) }
            if id != nil {
                Button("Delete", role: .destructive) { confirmDelete = true }
                    .accessibilityIdentifier("delete")
            }
            if let e = session.error { Text(e).foregroundStyle(.red) }
        }
        .navigationTitle(id == nil ? "New login" : "Edit")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { done(false) } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { Task { if await session.save(id: id, data) { done(false) } } }
                    .disabled(data.title.isEmpty)
            }
        }
        .confirmationDialog("Delete this item?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                if let id { Task { if await session.delete(id) { done(true) } } }
            }
        }
    }
}

extension LoginData {
    static let empty = LoginData(title: "", username: "", password: "", url: "", notes: "")
}
