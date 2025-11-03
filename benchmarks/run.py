import os, statistics
from importlib.resources import files
from promptdefender.detector import Detector

bank = os.getenv("BANK", "default").lower()
att_name = "attack_bank_round2.txt" if bank == "round2" else "attack_bank.txt"
ben_name = "benign_bank_round2.txt" if bank == "round2" else "benign_bank.txt"

ATT = files("promptdefender").joinpath(f"assets/{att_name}").read_text(encoding="utf-8").splitlines()
BEN = files("promptdefender").joinpath(f"assets/{ben_name}").read_text(encoding="utf-8").splitlines()

def score(decision):  # positive if attack
    return 1 if decision in ("SANITIZE","DENY") else 0

def main():
    det = Detector()
    tp = sum(score(det.analyze(x).decision) for x in ATT)
    fn = len(ATT) - tp
    fp = sum(score(det.analyze(x).decision) for x in BEN)
    tn = len(BEN) - fp
    prec = tp / (tp + fp) if (tp+fp) else 0.0
    rec  = tp / (tp + fn) if (tp+fn) else 0.0
    f1   = (2*prec*rec)/(prec+rec) if prec+rec else 0.0
    print(f"Attacks: TP={tp} FN={fn} | Benign: FP={fp} TN={tn}")
    print(f"Precision={prec:.2f} Recall={rec:.2f} F1={f1:.2f}")

if __name__ == "__main__":
    main()
