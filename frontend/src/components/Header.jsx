import React from "react";
import { SeverityBadge } from "./Badges";
import { formatTime } from "../utils/helpers";

export const Header = ({
  plants,
  currentPlantId,
  onPlantChange,
  user,
  guideOn,
  setGuideOn,
  notifOpen,
  setNotifOpen,
  onSignOut,
  openFindingsCount,
  liveEvents,
  findings,
  t0
}) => {
  const initials = user?.name
    ? user.name
        .split(" ")
        .map((w) => w[0])
        .join("")
        .slice(0, 2)
    : "US";

  const notifications = [
    ...liveEvents.slice(0, 4).map((x) => ({ sev: x.sev, title: x.title, meta: formatTime(x.t, t0) })),
    ...findings.slice(0, 3).map((x) => ({ sev: x.sev, title: x.title, meta: x.asset }))
  ];

  const allowedPlants = plants.filter((p) => user?.plants?.includes(p.id));

  return (
    <>
      <header>
        <select
          className="ws"
          id="pl"
          aria-label="Plant"
          value={currentPlantId}
          disabled={allowedPlants.length <= 1}
          onChange={(e) => onPlantChange(Number(e.target.value))}
        >
          {allowedPlants.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>

        <span className="badge" id="lv">
          <span className="dot" style={{ color: "var(--ok)" }}>
            ●
          </span>{" "}
          Simulation mode
        </span>

        <span className="sp"></span>

        <button className="badge" id="gd" onClick={() => setGuideOn(!guideOn)}>
          Guided tour
        </button>

        <button className="badge" id="bell" aria-label="Notifications" onClick={() => setNotifOpen(!notifOpen)}>
          {openFindingsCount} open findings
        </button>

        <span className="badge" id="who">
          <b>{user.name}</b> · {user.role}
        </span>

        <button className="badge" id="so" onClick={onSignOut}>
          Sign out
        </button>

        <div className="av" id="av">
          {initials}
        </div>
      </header>

      {notifOpen && (
        <div id="np" className="np">
          <b>Notifications</b>
          {notifications.length ? (
            notifications.map((item, idx) => (
              <div key={idx} className="row2" style={{ margin: "8px 0 0" }}>
                <SeverityBadge sev={item.sev} />
                <span style={{ flex: 1 }}>{item.title}</span>
                <span className="mono" style={{ color: "var(--mut)" }}>
                  {item.meta}
                </span>
              </div>
            ))
          ) : (
            <div className="empty">Nothing new.</div>
          )}
        </div>
      )}
    </>
  );
};

