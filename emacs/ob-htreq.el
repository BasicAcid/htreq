;;; ob-htreq.el --- Org-babel support for htreq -*- lexical-binding: t; -*-

;; Copyright (C) 2025 David Tabarie

;; Author: David Tabarie
;; Keywords: http, org, babel, tools
;; Version: 0.1.0
;; Package-Requires: ((emacs "24.4") (org "9.0"))
;; URL: https://github.com/BasicAcid/htreq

;; This package provides org-babel integration for htreq, allowing you to
;; execute HTTP requests directly from org-mode code blocks.

(require 'ob)
(require 'org)

;; Declare as part of org-babel languages
(defvar org-babel-default-header-args:htreq
  '((:results . "output")
    (:exports . "both"))
  "Default header arguments for htreq code blocks.")

(defcustom ob-htreq-binary "htreq"
  "Path to the htreq binary.
Can be an absolute path or a binary name in PATH."
  :type 'string
  :group 'org-babel)

(defun org-babel-execute:htreq (body params)
  "Execute an htreq code block with BODY and PARAMS.
This function is called by org-babel when evaluating htreq source blocks."
  (let* ((htreq-bin (or (cdr (assoc :htreq-bin params)) ob-htreq-binary))
         (processed-body (org-babel-expand-body:htreq body params))
         (temp-file (org-babel-temp-file "htreq-" ".http"))
         (cmd (org-babel-htreq-build-command htreq-bin temp-file params)))

    ;; Write request to temp file
    (with-temp-file temp-file
      (insert processed-body))

    ;; Debug: print command
    (message "ob-htreq: executing command: %s" cmd)
    (message "ob-htreq: temp file: %s" temp-file)

    ;; Execute htreq and return output
    (unwind-protect
        (let ((result (shell-command-to-string cmd)))
          ;; Strip CRLF (convert \r\n to \n) for cleaner display in org-mode
          (replace-regexp-in-string "\r\n" "\n" result))
      ;; Clean up temp file
      (when (file-exists-p temp-file)
        (delete-file temp-file)))))

(defun org-babel-expand-body:htreq (body params)
  "Expand BODY according to PARAMS for htreq.
Handles variable substitution from :var parameters."
  (let ((vars (org-babel--get-vars params)))
    (if vars
        (org-babel-htreq-substitute-vars body vars)
      body)))

(defun org-babel-htreq-substitute-vars (body vars)
  "Substitute variables in BODY from VARS alist.
Replaces $varname and ${varname} with values from VARS."
  (let ((result body))
    (dolist (var vars)
      (let ((name (symbol-name (car var)))
            (value (cdr var)))
        ;; Handle ${varname} format
        (setq result (replace-regexp-in-string
                      (regexp-quote (concat "${" name "}"))
                      (format "%s" value)
                      result t t))
        ;; Handle $varname format (but not ${ to avoid double substitution)
        (setq result (replace-regexp-in-string
                      (concat "\\$" (regexp-quote name) "\\b")
                      (format "%s" value)
                      result t))))
    result))

(defun org-babel-htreq-build-command (htreq-bin file params)
  "Build htreq command string with HTREQ-BIN, FILE, and PARAMS."
  (let ((args (list htreq-bin)))

    ;; Add target if specified (goes before flags)
    (let ((target (cdr (assoc :target params))))
      (when target
        (setq args (append args (list target)))))

    ;; Boolean flags
    (when (assoc :no-tls params)
      (setq args (append args '("--no-tls"))))
    (when (assoc :tls params)
      (setq args (append args '("--tls"))))
    (when (assoc :http2 params)
      (setq args (append args '("--http2"))))
    (when (assoc :http3 params)
      (setq args (append args '("--http3"))))
    (when (assoc :websocket params)
      (setq args (append args '("--websocket"))))
    (when (assoc :dump-frames params)
      (setq args (append args '("--dump-frames"))))
    (when (assoc :no-verify params)
      (setq args (append args '("--no-verify"))))
    (when (assoc :dump-tls params)
      (setq args (append args '("--dump-tls"))))
    (when (assoc :head params)
      (setq args (append args '("--head"))))
    (when (assoc :body params)
      (setq args (append args '("--body"))))
    (when (assoc :quiet params)
      (setq args (append args '("--quiet"))))
    (when (assoc :verbose params)
      (setq args (append args '("--verbose"))))
    (when (assoc :timing params)
      (setq args (append args '("--timing"))))
    (when (assoc :follow params)
      (setq args (append args '("--follow"))))
    (when (assoc :print-request params)
      (setq args (append args '("--print-request"))))
    (when (assoc :no-alt-svc params)
      (setq args (append args '("--no-alt-svc"))))
    (when (assoc :no-color params)
      (setq args (append args '("--no-color"))))

    ;; Value flags
    (let ((env-file (cdr (assoc :env-file params))))
      (when env-file
        (setq args (append args (list (concat "--env-file=" env-file))))))

    (let ((max-bytes (cdr (assoc :max-bytes params))))
      (when max-bytes
        (setq args (append args (list (format "--max-bytes=%s" max-bytes))))))

    (let ((timeout (cdr (assoc :timeout params))))
      (when timeout
        (setq args (append args (list (format "--timeout=%ss" timeout))))))

    (let ((user (cdr (assoc :user params))))
      (when user
        (setq args (append args (list (format "--user=%s" user))))))

    (let ((retry (cdr (assoc :retry params))))
      (when retry
        (setq args (append args (list (format "--retry=%s" retry))))))

    (let ((retry-delay (cdr (assoc :retry-delay params))))
      (when retry-delay
        (setq args (append args (list (format "--retry-delay=%s" retry-delay))))))

    (let ((max-redirects (cdr (assoc :max-redirects params))))
      (when max-redirects
        (setq args (append args (list (format "--max-redirects=%s" max-redirects))))))

    (let ((unix-socket (cdr (assoc :unix-socket params))))
      (when unix-socket
        (setq args (append args (list (format "--unix-socket=%s" unix-socket))))))

    ;; Add -f and file at the end
    (setq args (append args (list "-f" file)))

    ;; Build command string
    (mapconcat 'shell-quote-argument args " ")))

;; Add to list of org-babel languages
(add-to-list 'org-src-lang-modes '("htreq" . http))

(provide 'ob-htreq)
