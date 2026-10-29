import React, { useState } from "react";
import { TagBadge } from "../components/Badges";
import { parsePdfText, readPdfFile } from "../utils/helpers";

const FIELDS = [
  ["id", "Asset ID"],
  ["name", "Name"],
  ["mfr", "Manufacturer"],
  ["model", "Model"],
  ["fw", "Firmware"],
  ["proto", "Protocols"],
  ["ifc", "Interfaces"],
  ["sec", "Security features"],
  ["life", "Lifecycle statement"]
];

export const AssetExplorer = ({
  assets,
  onSaveAsset,
  selectedAssetId,
  onSelectAsset,
  draft,
  setDraft,
  searchQuery,
  setSearchQuery
}) => {
  const [fileError, setFileError] = useState("");
  const [fileSuccess, setFileSuccess] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [draftForm, setDraftForm] = useState(null);
  const [draftError, setDraftError] = useState("");

  const getNextId = () => {
    let n = assets.length + 1;
    const format = (num) => `AST-${String(num).padStart(2, "0")}`;
    while (assets.some((a) => a.id === format(n))) n++;
    return format(n);
  };

  const handleFileChange = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const name = f.name.toLowerCase();
    if (!name.endsWith(".pdf")) {
      setFileError("Unsupported file type. Use .pdf.");
      setFileSuccess(false);
      setSelectedFile(null);
    } else if (f.size > 20 * 1048576) {
      setFileError(`File is ${(f.size / 1048576).toFixed(1)} MB. The limit is 20 MB.`);
      setFileSuccess(false);
      setSelectedFile(null);
    } else {
      setSelectedFile(f);
      setFileError("File passed checks. Click Add to inventory to read it.");
      setFileSuccess(true);
    }
  };

  const handleReadPdf = async () => {
    if (!selectedFile) {
      setFileError("Choose a PDF file first.");
      setFileSuccess(false);
      return;
    }
    setFileError(`Reading ${selectedFile.name}...`);
    setFileSuccess(false);

    const d = {
      id: getNextId(),
      src: selectedFile.name,
      name: "",
      mfr: "",
      model: "",
      fw: "",
      proto: "",
      ifc: "",
      sec: "",
      life: ""
    };

    try {
      const text = await readPdfFile(selectedFile);
      const parsed = parsePdfText(text);
      Object.assign(d, parsed);
      setDraftForm(d);
      setFileError(`Read ${selectedFile.name}. Check each value below before saving.`);
      setFileSuccess(true);
    } catch {
      setDraftForm(d);
      setFileError("Could not read text from this PDF, so the fields are empty. Fill them in by hand.");
      setFileSuccess(false);
    }
  };

  const handleManualAdd = () => {
    const d = {
      id: getNextId(),
      src: "manual entry",
      name: "",
      mfr: "",
      model: "",
      fw: "",
      proto: "",
      ifc: "",
      sec: "",
      life: ""
    };
    setDraftForm(d);
  };

  // Synchronize external draft if set (e.g. from live discovery)
  React.useEffect(() => {
    if (draft) {
      setDraftForm({
        id: draft.id || getNextId(),
        src: draft.src || "live discovery",
        name: draft.name || "",
        mfr: draft.mfr || "",
        model: draft.model || "",
        fw: draft.fw || "",
        proto: draft.proto || "",
        ifc: draft.ifc || "",
        sec: draft.sec || "",
        life: draft.life || ""
      });
      setDraft(null);
    }
  }, [draft, setDraft]);

  const handleSaveDraft = async () => {
    if (!draftForm) return;
    const id = (draftForm.id || "").trim();
    const name = (draftForm.name || "").trim();

    if (!id || !name) {
      setDraftError("Asset ID and name are required.");
      return;
    }
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(id)) {
      setDraftError("Asset ID can use letters, numbers, - and _ only (32 characters max).");
      return;
    }
    if (assets.some((a) => a.id === id)) {
      setDraftError(`Asset ID ${id} already exists. Choose another.`);
      return;
    }

    try {
      await onSaveAsset({
        id,
        name,
        mfr: draftForm.mfr?.trim() || null,
        model: draftForm.model?.trim() || null,
        fw: draftForm.fw?.trim() || null,
        proto: draftForm.proto?.trim() || null,
        ifc: draftForm.ifc?.trim() || null,
        sec: draftForm.sec?.trim() || null,
        life: draftForm.life?.trim() || null,
        ver: false,
        src: draftForm.src
      });

      setDraftForm(null);
      setDraftError("");
    } catch (err) {
      setDraftError(err.message || "Failed to save asset.");
    }
  };

  const filteredAssets = assets.filter((a) =>
    (a.id + a.name + (a.mfr || "") + (a.model || "")).toLowerCase().includes(searchQuery.toLowerCase())
  );

  const selectedAsset = selectedAssetId ? assets.find((a) => a.id === selectedAssetId) : null;
  const renderUnknown = (val) => (val ? val : <span className="unk">Unknown, not verified</span>);

  return (
    <div>
      <h1>OT Asset Explorer</h1>
      <p className="sub">
        Upload a datasheet, review what was extracted, then fix anything that is wrong. Missing values stay marked as unknown.
      </p>

      {/* PDF Drop / Input */}
      <div className="drop" id="drop1">
        Drop a PDF datasheet here (max 20 MB)
        <br />
        <input type="file" id="f1" accept=".pdf" aria-label="Datasheet PDF" onChange={handleFileChange} />{" "}
        <button className="btn" id="a1" onClick={handleReadPdf}>
          Add to inventory
        </button>{" "}
        <button className="btn ghost" id="am" onClick={handleManualAdd}>
          Add asset manually
        </button>
      </div>

      <div className="err" id="e1" style={{ color: fileSuccess ? "var(--ok)" : "" }}>
        {fileError}
      </div>

      {/* Draft Form */}
      {draftForm && (
        <div className="card" style={{ marginTop: "16px" }}>
          <h2>
            Review before saving <TagBadge kind="needs_review" />
          </h2>
          <p className="sub" style={{ marginBottom: "12px" }}>
            Source: {draftForm.src}. Leave a field empty if the document does not say. It will show as unknown.
          </p>
          <div className="grid g2" style={{ gap: "10px" }}>
            {FIELDS.map(([k, label]) => (
              <label key={k}>
                {label}
                <input
                  id={`d_${k}`}
                  style={{ width: "100%" }}
                  value={draftForm[k] || ""}
                  onChange={(e) => setDraftForm({ ...draftForm, [k]: e.target.value })}
                />
              </label>
            ))}
          </div>
          <div className="err" id="ed">
            {draftError}
          </div>
          <div className="row2" style={{ marginTop: "8px" }}>
            <button className="btn" id="sv" onClick={handleSaveDraft}>
              Save asset
            </button>
            <button className="btn ghost" id="cx" onClick={() => setDraftForm(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Inventory Table */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Asset inventory</h2>
        <p className="hint">
          Every controller, RTU and HMI known to this plant. Values taken from datasheets stay marked until an analyst verifies them.
        </p>
        <div className="row2">
          <input
            id="q"
            placeholder="Search assets"
            value={searchQuery}
            aria-label="Search assets"
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Manufacturer</th>
                <th>Model</th>
                <th>Firmware</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.length ? (
                filteredAssets.map((a) => (
                  <tr
                    key={a.id}
                    className="row"
                    data-a={a.id}
                    onClick={() => onSelectAsset(a.id)}
                    style={{ background: selectedAssetId === a.id ? "var(--panel2)" : undefined }}
                  >
                    <td className="mono">{a.id}</td>
                    <td>{a.name}</td>
                    <td>{renderUnknown(a.mfr === "Unknown" ? 0 : a.mfr)}</td>
                    <td>{renderUnknown(a.model === "Unknown" ? 0 : a.model)}</td>
                    <td className="mono">{renderUnknown(a.fw)}</td>
                    <td>{a.ver ? <TagBadge kind="extracted" /> : <TagBadge kind="needs_review" />}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="empty">
                    No assets match that search. Clear the search or upload a datasheet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Asset Details Card */}
      {selectedAsset && (
        <div className="card" style={{ marginTop: "16px" }}>
          <h2>
            {selectedAsset.id}: {selectedAsset.name}
          </h2>
          <p className="hint">Fields read from the datasheet. Unknown values are shown as unknown and never guessed.</p>
          <div className="grid g2" style={{ gap: "8px" }}>
            {[
              ["Protocols", selectedAsset.proto],
              ["Interfaces", selectedAsset.ifc],
              ["Security features", selectedAsset.sec],
              ["Lifecycle statement", selectedAsset.life],
              ["Source", selectedAsset.src]
            ].map(([k, v]) => (
              <div key={k}>
                <div className="sub" style={{ margin: 0 }}>
                  {k}
                </div>
                {renderUnknown(v)}
              </div>
            ))}
          </div>
          <p className="note" style={{ marginTop: "12px" }}>
            Extracted values come from the document text only. Vulnerability status is not checked here.
          </p>
        </div>
      )}
    </div>
  );
};

