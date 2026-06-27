#!/usr/bin/env python3
"""
lstm_wrapper.py — Wrapper sklearn-compatible pour le modèle Keras/LSTM
Permet la sauvegarde et le chargement via joblib/pickle.
Ce fichier DOIT être dans le même répertoire que train_model.py et ryu_ml_ddos_v3.py
"""
import numpy as np

class LSTMWrapper:
    """
    Encapsule un modèle Keras LSTM dans une interface sklearn-like.
    predict_proba(X) → probabilités DDoS [N, 2]
    predict(X)       → labels binaires [N]
    """
    def __init__(self, keras_model, scaler, n_features):
        self.keras_model = keras_model
        self.scaler      = scaler
        self.n_features  = n_features

    def predict_proba(self, X):
        X_s = self.scaler.transform(X)
        X_r = X_s.reshape(-1, 1, self.n_features)
        proba = self.keras_model.predict(X_r, verbose=0).flatten()
        return np.column_stack([1 - proba, proba])

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)

    def __getstate__(self):
        """Sérialisation : sauvegarder les poids Keras dans un buffer."""
        import io, tempfile, os
        state = self.__dict__.copy()
        # Sauvegarder le modèle Keras dans un buffer binaire
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "model.keras")
            try:
                self.keras_model.save(path)
                with open(path, "rb") as f:
                    state["_keras_bytes"] = f.read()
            except Exception:
                state["_keras_bytes"] = None
        state.pop("keras_model", None)
        return state

    def __setstate__(self, state):
        """Désérialisation : reconstruire le modèle Keras depuis le buffer."""
        keras_bytes = state.pop("_keras_bytes", None)
        self.__dict__.update(state)
        if keras_bytes:
            import tempfile, os
            try:
                from tensorflow.keras.models import load_model
                with tempfile.TemporaryDirectory() as tmp:
                    path = os.path.join(tmp, "model.keras")
                    with open(path, "wb") as f:
                        f.write(keras_bytes)
                    self.keras_model = load_model(path)
            except Exception as e:
                print(f"[LSTMWrapper] Erreur chargement Keras : {e}")
                self.keras_model = None
        else:
            self.keras_model = None
