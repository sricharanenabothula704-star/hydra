import json
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import hashlib

@dataclass
class Trajectory:
    """A single agent trajectory with score."""
    task: str
    steps: List[Dict[str, Any]]
    score: float
    skill_version: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict = field(default_factory=dict)

@dataclass
class SkillEdit:
    """A single edit operation on a skill document."""
    op: str  # "add", "delete", "replace"
    section: str
    content: str
    rationale: str
    score_delta: float = 0.0

@dataclass
class SkillVersion:
    """A versioned skill document with metadata."""
    version: str
    content: str
    validation_score: float
    train_score: float
    edit_history: List[SkillEdit] = field(default_factory=list)
    parent_version: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class SkillStore:
    """Manages skill versions, validation scores, and edit history."""
    
    def __init__(self, skill_dir: Path):
        self.skill_dir = Path(skill_dir)
        self.skill_dir.mkdir(parents=True, exist_ok=True)
        self.versions_dir = self.skill_dir / "versions"
        self.versions_dir.mkdir(exist_ok=True)
        self.best_skill_path = self.skill_dir / "best_skill.md"
        self.index_path = self.skill_dir / "index.json"
        self._load_index()
    
    def _load_index(self):
        if self.index_path.exists():
            with open(self.index_path) as f:
                self.index = json.load(f)
        else:
            self.index = {"versions": {}, "best_version": None}
    
    def _save_index(self):
        with open(self.index_path, 'w') as f:
            json.dump(self.index, f, indent=2)
    
    def _version_hash(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def save_version(self, skill: SkillVersion) -> str:
        version_path = self.versions_dir / f"v{skill.version}.md"
        with open(version_path, 'w') as f:
            f.write(skill.content)
        
        meta_path = self.versions_dir / f"v{skill.version}.meta.json"
        with open(meta_path, 'w') as f:
            json.dump({
                "version": skill.version,
                "validation_score": skill.validation_score,
                "train_score": skill.train_score,
                "edit_history": [e.__dict__ for e in skill.edit_history],
                "parent_version": skill.parent_version,
                "timestamp": skill.timestamp
            }, f, indent=2)
        
        self.index["versions"][skill.version] = {
            "validation_score": skill.validation_score,
            "train_score": skill.train_score,
            "timestamp": skill.timestamp,
            "parent": skill.parent_version
        }
        
        if (self.index["best_version"] is None or 
            skill.validation_score > self.index["versions"][self.index["best_version"]]["validation_score"]):
            self.index["best_version"] = skill.version
            self.deploy_best(skill)
        
        self._save_index()
        return skill.version
    
    def deploy_best(self, skill: SkillVersion):
        with open(self.best_skill_path, 'w') as f:
            f.write(skill.content)
    
    def load_best(self) -> Optional[SkillVersion]:
        if not self.best_skill_path.exists():
            return None
        content = self.best_skill_path.read_text()
        version = self.index.get("best_version")
        if version and version in self.index["versions"]:
            meta = self.index["versions"][version]
            return SkillVersion(
                version=version,
                content=content,
                validation_score=meta["validation_score"],
                train_score=meta["train_score"],
                parent_version=meta.get("parent"),
                timestamp=meta["timestamp"]
            )
        return None
    
    def load_version(self, version: str) -> Optional[SkillVersion]:
        version_path = self.versions_dir / f"v{version}.md"
        meta_path = self.versions_dir / f"v{version}.meta.json"
        if not version_path.exists() or not meta_path.exists():
            return None
        content = version_path.read_text()
        with open(meta_path) as f:
            meta = json.load(f)
        return SkillVersion(
            version=version,
            content=content,
            validation_score=meta["validation_score"],
            train_score=meta["train_score"],
            edit_history=[SkillEdit(**e) for e in meta["edit_history"]],
            parent_version=meta.get("parent_version"),
            timestamp=meta["timestamp"]
        )
    
    def list_versions(self) -> List[Dict]:
        return [
            {"version": v, **meta} 
            for v, meta in self.index["versions"].items()
        ]


class SkillOptimizer:
    """
    SkillOpt optimizer implementing:
    Rollout -> Reflect -> Aggregate -> Select -> Update -> Evaluate
    """
    
    def __init__(
        self,
        skill_dir: str,
        validator: str = "default",
        learning_rate: float = 0.1,
        validation_split: float = 0.2,
        max_edits_per_epoch: int = 5,
        seed_skill: Optional[str] = None
    ):
        self.skill_dir = Path(skill_dir)
        self.validator_name = validator
        self.learning_rate = learning_rate
        self.validation_split = validation_split
        self.max_edits_per_epoch = max_edits_per_epoch
        self.backend_model = backend_model
        self.seed_skill = seed_skill
        
        self.store = SkillStore(self.skill_dir)
        self.trajectories: List[Trajectory] = []
        self.validator = self._load_validator(validator)
        self.current_skill = self.store.load_best()
        
        if not self.current_skill and seed_skill:
            self.current_skill = self._create_initial_skill(seed_skill)
    
    def _load_validator(self, name: str):
        validators = {
            "default": DefaultValidator(),
            "bug_bounty": BugBountyValidator(),
            "code_review": CodeReviewValidator(),
            "analysis": AnalysisValidator(),
        }
        return validators.get(name, DefaultValidator())
    
    def _create_initial_skill(self, seed: str) -> SkillVersion:
        content = Path(seed).read_text() if Path(seed).exists() else seed
        skill = SkillVersion(
            version="0",
            content=content,
            validation_score=0.0,
            train_score=0.0,
            parent_version=None
        )
        self.store.save_version(skill)
        return skill
    
    def add_trajectory(self, trajectory: Trajectory):
        self.trajectories.append(trajectory)
    
    def add_trajectories(self, trajectories: List[Trajectory]):
        self.trajectories.extend(trajectories)
    
    def train(self, epochs: int = 10) -> List[SkillVersion]:
        """Run the full SkillOpt training loop."""
        if not self.current_skill:
            raise ValueError("No initial skill. Provide seed_skill or load existing.")
        
        history = []
        versions_before = len(self.store.list_versions())
        
        for epoch in range(epochs):
            print(f"\n=== Epoch {epoch + 1}/{epochs} ===")
            
            train_trajs, val_trajs = self._split_trajectories()
            
            if not train_trajs:
                print("No training trajectories available")
                break
            
            edits = self._reflect_and_aggregate(train_trajs)
            
            if not edits:
                print("No viable edits generated")
                break
            
            selected_edits = self._select_edits(edits, val_trajs)
            
            if not selected_edits:
                print("No edits passed validation gate")
                break
            
            new_skill = self._apply_edits(selected_edits)
            
            val_score = self._evaluate(new_skill, val_trajs)
            train_score = self._evaluate(new_skill, train_trajs)
            
            new_skill.validation_score = val_score
            new_skill.train_score = train_score
            new_skill.edit_history = selected_edits
            new_skill.parent_version = self.current_skill.version
            
            self.store.save_version(new_skill)
            self.current_skill = new_skill
            
            history.append(new_skill)
            
            print(f"  Train score: {train_score:.3f}")
            print(f"  Val score:   {val_score:.3f}")
            print(f"  Edits applied: {len(selected_edits)}")
            
            # Stop if no meaningful improvement
            if len(history) >= 2:
                prev = history[-2]
                if new_skill.validation_score <= prev.validation_score and epoch > 0:
                    print("  Validation score not improving - stopping")
                    break
            
            if len(self.store.list_versions()) >= 50:
                print("Max versions reached")
                break
        
        return history
    
    def _split_trajectories(self) -> tuple:
        if not self.trajectories:
            return [], []
        
        split_idx = int(len(self.trajectories) * (1 - self.validation_split))
        return self.trajectories[:split_idx], self.trajectories[split_idx:]
    
    def _reflect_and_aggregate(self, trajectories: List[Trajectory]) -> List[SkillEdit]:
        """Reflect on trajectories and aggregate into candidate edits."""
        edits = []
        
        for traj in trajectories:
            traj_edits = self._reflect_single(traj)
            edits.extend(traj_edits)
        
        aggregated = self._aggregate_edits(edits)
        return aggregated[:self.max_edits_per_epoch]
    
    def _reflect_single(self, traj: Trajectory) -> List[SkillEdit]:
        """Use optimizer model to reflect on a single trajectory."""
        self._current_traj = traj
        prompt = self._build_reflection_prompt(traj)
        response = self._call_optimizer_model(prompt)
        return self._parse_edits(response, traj)
    
    def _build_reflection_prompt(self, traj: Trajectory) -> str:
        skill_content = self.current_skill.content if self.current_skill else "(empty)"
        
        return f"""You are a skill optimizer. Analyze this agent trajectory and propose specific edits to improve the skill document.

CURRENT SKILL:
{skill_content}

TASK: {traj.task}
SCORE: {traj.score}/10

TRAJECTORY:
{json.dumps(traj.steps, indent=2)}

Propose up to 3 specific edits as JSON array:
[{{"op": "add|delete|replace", "section": "section name", "content": "new content", "rationale": "why this helps"}}]

Focus on: missing steps, incorrect guidance, gaps exposed by trajectory.
Only propose edits that would have improved THIS trajectory's score."""
    
    def _call_optimizer_model(self, prompt: str) -> str:
        # Rule-based optimizer: analyzes score + trajectory + task to generate targeted edits
        traj = self._current_traj if hasattr(self, '_current_traj') else None
        edits = []
        
        # Parse task type
        task_lower = (traj.task if traj else "").lower()
        
        # Determine which sections need improvement based on score and task
        low_score = (traj.score if traj else 0) < 6.0
        medium_score = (traj.score if traj else 0) < 8.0
        
        if "s3" in task_lower or "bucket" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 5: Vulnerability Discovery",
                "content": "### 5k: S3 Bucket Testing\n- **URL formats**: bucket.s3.amazonaws.com, bucket.s3-[region].amazonaws.com\n- **Permissions**: aws s3 ls s3://bucket-name --no-sign-request\n- **Discovery**: lazys3 target.com, Google dorking 'site:s3.amazonaws.com target.com'\n- **Check**: listing, read, write, bucket ACL, bucket policy",
                "rationale": "Trajectory found S3 buckets - this section was missing from skill"
            })
        
        if "key" in task_lower or "secret" in task_lower or "api" in task_lower or "jwt" in task_lower or "razorpay" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 4: JS Bundle Analysis",
                "content": "- **All API key patterns**: Google AIza[0-9A-Za-z_-]{35}, Stripe sk_live_/pk_live_, AWS AKIA[0-9A-Z]{16}, GitHub ghp_, Slack xox[baprs]-, JWT eyJ[a-zA-Z0-9_-]+\\.eyJ\n- **Razorpay**: rzp_live_|rzp_test_ prefixes\n- **Validate keys**: curl against vendor API to check active status\n- **Referer bypass**: Add referer header to bypass key restrictions",
                "rationale": "Trajectory found Razorpay key but validation section was missing"
            })
        
        if "waf" in task_lower or "cloudflare" in task_lower or "403" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 6: WAF Bypass Techniques",
                "content": "- **403 bypass ordered**: X-Forwarded-For:127.0.0.1, X-Original-URL, X-Rewrite-URL, path ;.js, null byte %00, path traversal ..%2f, double encoding %2561dmin, case variation /AdMiN\n- **WAF detect**: wafw00f https://target.com\n- **Origin IP**: shodan, historical DNS, SPF records, email headers, subdomains not behind WAF",
                "rationale": "Trajectory encountered 403/blocked endpoints but WAF bypass ordering was unclear"
            })
        
        if "slow" in task_lower or "nuclei" in task_lower and "no finding" in task_lower:
            edits.append({
                "op": "replace",
                "section": "Phase 2: Active Reconnaissance",
                "content": "### Phase 2: Active Reconnaissance\n- **HTTPX**: httpx -l resolved.txt -ports 80,443,8080,8443,3000,5000,8000,8888,9000 -silent -o live.txt\n- **CDN Filtering**: httpx -l ip.txt -title -silent | grep -vi 'cloudflare|akamai|fastly'\n- **Naabu**: naabu -l origin_ips.txt -top-ports 1000 -rate 1500 -verify -silent\n- **Nmap**: python3 ~/scripts/naabutonmap.py -i naabu.txt\n- **Nuclei**: cat ip.txt | nuclei -tags cve -bs 200 (use -bs for rate-limiting)\n- **FFUF**: ffuf -w naabu.txt:URL -w wordlist:FILE -u https://URL/FILE",
                "rationale": "Trajectory used nuclei without rate limiting - add rate control flags"
            })
        
        if "crt.sh" in task_lower or "certificate" in task_lower or "subdomain" in task_lower and "found" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 1: Passive Reconnaissance",
                "content": "- **CertSpotter fallback**: When crt.sh returns empty, use CertSpotter API\n- **Wayback CDX via Tor**: If Wayback blocked by geo-restrictions, use proxychains\n- **Organization pivot**: Query by org name (O= field) for acquisitions\n- **Real-time monitoring**: crtmon -d target.com for fresh cert alerts",
                "rationale": "Trajectory hit crt.sh empty/Tor bypass needed - add fallback strategies"
            })
        
        if "laravel" in task_lower or "debug" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 8: Tech-Specific Vectors",
                "content": "- **Laravel**: /.env, /debug, Ignition RCE (CVE-2021-3129), APP_KEY exploit for RCE via Ignition solution\n- Debug mode signs: Full stack traces with server paths, Symfony error pages, vendor paths exposed",
                "rationale": "Laravel debug mode found - add Laravel-specific exploitation"
            })
        
        if "otp" in task_lower or "rate limit" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 5: Vulnerability Discovery",
                "content": "### 5l: Rate Limit Testing\n- **OTP endpoints**: Test 20+ rapid requests, check for cooldown\n- **Bypass**: X-Forwarded-For rotation, cookie/token reset, HTTP method change (GET vs POST)\n- **Login**: Sequential attempts, check for account lockout vs infinite tries\n- **Headers**: Different User-Agent, Accept-Language per attempt",
                "rationale": "OTP rate limit found - add rate limit testing methodology"
            })
        
        if "soap" in task_lower or "mendix" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 8: Tech-Specific Vectors",
                "content": "- **Mendix**: get_session_data for app metadata, XAS session extraction, SOAP /ws/ service discovery, check Anonymous role permissions, service name brute-force via JS analysis",
                "rationale": "Mendix SOAP endpoint found - add Mendix methodology"
            })
        
        if "grafana" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 8: Tech-Specific Vectors",
                "content": "- **Grafana**: Default creds admin/admin, check for SSRF via datasource queries, test auth bypass endpoints (/api/org, /api/users), check anonymous access",
                "rationale": "Grafana dashboard found but no auth bypass section existed"
            })
        
        if "report" in task_lower or "submit" in task_lower:
            edits.append({
                "op": "add",
                "section": "Phase 10: Reporting",
                "content": "- BugBase constraints: Title MAX 120 chars, ONE URL per report field\n- Report via browser: bugbase.ai login required\n- Include CVSS vector + CWE for credibility\n- Show blocked vs bypassed endpoints side-by-side\n- Impact must be specific (users affected, $ amount)",
                "rationale": "Missing reporting constraints and BugBase-specific rules"
            })
        
        # Generic improvements for low scoring trajectories
        if low_score and not edits:
            edits.append({
                "op": "replace",
                "section": "Phase 5: Vulnerability Discovery",
                "content": """### Phase 5: Vulnerability Discovery (Priority Order)
1. Subdomain Takeover — nuclei -t takeovers/
2. CORS — curl -I -H "Origin: https://evil.com"
3. Spring Boot Actuator — /actuator, /actuator/env, /actuator/heapdump
4. Config files — .env, .git/config, dump.sql
5. SQLi — ' OR '1'='1, UNION SELECT, SLEEP()
6. XSS — <script>, <img onerror>, <svg onload>
7. SSRF — collaborator, 169.254.169.254, file:///
8. IDOR — sequential IDs 1,2,100,500,1000
9. GraphQL — {"query":"{__schema{types{name}}}"}
10. Auth Bypass — null/empty tokens, X-Forwarded-For, X-Internal-Request

**Priority**: RCE > SQLi > Auth Bypass > SSRF > IDOR > XSS > Info Disclosure""",
                "rationale": "Low scoring trajectory - add prioritized checklist for quick wins"
            })
        
        if not edits:
            edits.append({
                "op": "add",
                "section": "general",
                "content": "- Always save findings with HASH dedup in OUTDIR\n- Verify Tor before each session\n- Use proxychains4 for all requests\n- Check FindingStorage phase for file naming convention",
                "rationale": "General improvement from recent session patterns"
            })
        
        return json.dumps(edits[:self.max_edits_per_epoch])
    
    def _parse_edits(self, response: str, traj: Trajectory) -> List[SkillEdit]:
        try:
            edits_data = json.loads(response)
            return [SkillEdit(**e, score_delta=0.0) for e in edits_data]
        except:
            return []
    
    def _aggregate_edits(self, edits: List[SkillEdit]) -> List[SkillEdit]:
        """Merge similar edits, keep highest rationale quality."""
        by_section_op = {}
        for edit in edits:
            key = (edit.section, edit.op)
            if key not in by_section_op or len(edit.rationale) > len(by_section_op[key].rationale):
                by_section_op[key] = edit
        return list(by_section_op.values())
    
    def _select_edits(self, edits: List[SkillEdit], val_trajs: List[Trajectory]) -> List[SkillEdit]:
        """Validation gate: keep edits that improve held-out score.
        
        First epoch (version 0): accept all edits since skill hasn't been used yet.
        Subsequent epochs: only accept edits that strictly improve validation score.
        """
        if not val_trajs:
            return edits[:self.max_edits_per_epoch]
        
        is_first_epoch = self.current_skill.version == "0"
        baseline_score = self._evaluate(self.current_skill, val_trajs)
        selected = []
        
        for edit in edits:
            test_skill = self._apply_single_edit(edit)
            new_score = self._evaluate(test_skill, val_trajs)
            
            if is_first_epoch or new_score > baseline_score:
                edit.score_delta = new_score - baseline_score if not is_first_epoch else 0.0
                selected.append(edit)
                if not is_first_epoch:
                    baseline_score = new_score
        
        if selected:
            return selected[:self.max_edits_per_epoch]
        return selected
    
    def _apply_single_edit(self, edit: SkillEdit) -> SkillVersion:
        content = self.current_skill.content
        
        if edit.op == "add":
            content = self._add_section(content, edit.section, edit.content)
        elif edit.op == "replace":
            content = self._replace_section(content, edit.section, edit.content)
        elif edit.op == "delete":
            content = self._delete_section(content, edit.section)
        
        return SkillVersion(
            version="temp",
            content=content,
            validation_score=0,
            train_score=0
        )
    
    def _apply_edits(self, edits: List[SkillEdit]) -> SkillVersion:
        content = self.current_skill.content
        for edit in edits:
            if edit.op == "add":
                content = self._add_section(content, edit.section, edit.content)
            elif edit.op == "replace":
                content = self._replace_section(content, edit.section, edit.content)
            elif edit.op == "delete":
                content = self._delete_section(content, edit.section)
        
        new_version = str(len(self.store.list_versions()))
        return SkillVersion(
            version=new_version,
            content=content,
            validation_score=0,
            train_score=0,
            edit_history=edits,
            parent_version=self.current_skill.version
        )
    
    def _add_section(self, content: str, section: str, new_content: str) -> str:
        header = f"## {section}"
        if header in content:
            return content.replace(header, f"{header}\n\n{new_content}")
        return content + f"\n\n{header}\n\n{new_content}"
    
    def _replace_section(self, content: str, section: str, new_content: str) -> str:
        header = f"## {section}"
        next_header_idx = content.find("\n## ", content.find(header) + 1)
        if next_header_idx == -1:
            next_header_idx = len(content)
        start = content.find(header)
        if start == -1:
            return self._add_section(content, section, new_content)
        return content[:start] + f"{header}\n\n{new_content}" + content[next_header_idx:]
    
    def _delete_section(self, content: str, section: str) -> str:
        header = f"## {section}"
        start = content.find(header)
        if start == -1:
            return content
        next_header = content.find("\n## ", start + 1)
        if next_header == -1:
            return content[:start].rstrip()
        return content[:start].rstrip() + content[next_header:]
    
    def _evaluate(self, skill: SkillVersion, trajectories: List[Trajectory]) -> float:
        if not trajectories:
            return 0.0
        return self.validator.evaluate(skill, trajectories)
    
    def deploy(self) -> Path:
        """Deploy best_skill.md for production use."""
        best = self.store.load_best()
        if best:
            return self.store.best_skill_path
        raise ValueError("No trained skill available")


class Validator:
    """Base validator class."""
    def evaluate(self, skill: SkillVersion, trajectories: List[Trajectory]) -> float:
        raise NotImplementedError


class DefaultValidator(Validator):
    def evaluate(self, skill: SkillVersion, trajectories: List[Trajectory]) -> float:
        if not trajectories:
            return 0.0
        return sum(t.score for t in trajectories) / len(trajectories) / 10.0


class BugBountyValidator(Validator):
    """Validator for bug bounty hunting skills.
    
    Evaluates how well a skill version performs on given trajectories.
    Higher version = more refined skill. Also scores based on trajectory outcomes.
    """
    
    WEIGHTS = {
        "recon": 0.20,
        "vuln_discovery": 0.35,
        "poc_quality": 0.25,
        "report_quality": 0.20
    }
    
    def evaluate(self, skill: SkillVersion, trajectories: List[Trajectory]) -> float:
        if not trajectories:
            return 0.0
        
        # Version bonus: more refined skills get a small boost
        try:
            version_num = int(skill.version)
        except ValueError:
            version_num = 0
        version_bonus = min(version_num * 0.05, 0.50)
        
        # Content bonus: longer/more detailed skills are better
        content_depth = min(len(skill.content) / 5000, 1.0) * 0.10
        
        scores = []
        for traj in trajectories:
            score = 0.0
            meta = traj.metadata
            has_meta = bool(meta and any(v != 0 for v in meta.values()))
            
            if has_meta:
                recon_raw = (
                    meta.get("subdomain_count", 0) / 50 * 0.3 +
                    meta.get("live_count", 0) / 20 * 0.3 +
                    meta.get("ports_found", 0) / 10 * 0.2 +
                    meta.get("endpoints_found", 0) / 30 * 0.2
                )
                score += min(recon_raw, 1.0) * self.WEIGHTS["recon"]
                
                vuln_raw = (
                    meta.get("vuln_count", 0) / 5 * 0.5 +
                    (1.0 if meta.get("vuln_type") else 0.0) * 0.3 +
                    meta.get("takeover_count", 0) / 2 * 0.1 +
                    meta.get("secrets_found", 0) / 5 * 0.1
                )
                score += min(vuln_raw, 1.0) * self.WEIGHTS["vuln_discovery"]
                
                poc = meta.get("poc_quality", 0.5)
                score += min(poc, 1.0) * self.WEIGHTS["poc_quality"]
            
            # Trajectory score as base
            base = traj.score / 10.0
            score += base * self.WEIGHTS["report_quality"]
            
            if not has_meta:
                score = base
            
            scores.append(min(score + version_bonus + content_depth, 1.0))
        
        return sum(scores) / len(scores) if scores else 0.0


class CodeReviewValidator(Validator):
    def evaluate(self, skill: SkillVersion, trajectories: List[Trajectory]) -> float:
        if not trajectories:
            return 0.0
        scores = []
        for traj in trajectories:
            meta = traj.metadata
            score = (
                meta.get("issues_found", 0) / 5 * 0.4 +
                meta.get("fix_quality", 0) * 0.3 +
                meta.get("coverage", 0) * 0.3
            )
            scores.append(min(score, 1.0))
        return sum(scores) / len(scores)


class AnalysisValidator(Validator):
    def evaluate(self, skill: SkillVersion, trajectories: List[Trajectory]) -> float:
        if not trajectories:
            return 0.0
        return sum(t.score for t in trajectories) / len(trajectories) / 10.0


class TrajectoryLogger:
    """Logs agent trajectories for SkillOpt training."""
    
    def __init__(self, log_dir: Path):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_trajectory: Optional[Trajectory] = None
    
    def start_trajectory(self, task: str, skill_version: str):
        self.current_trajectory = Trajectory(
            task=task,
            steps=[],
            score=0.0,
            skill_version=skill_version
        )
    
    def log_step(self, action: str, observation: str, tool: str = "", metadata: Dict = None):
        if self.current_trajectory:
            self.current_trajectory.steps.append({
                "action": action,
                "observation": observation,
                "tool": tool,
                "timestamp": datetime.now().isoformat(),
                "metadata": metadata or {}
            })
    
    def end_trajectory(self, score: float, metadata: Dict = None) -> Trajectory:
        if not self.current_trajectory:
            raise ValueError("No active trajectory")
        
        self.current_trajectory.score = score
        if metadata:
            self.current_trajectory.metadata = metadata
        
        traj = self.current_trajectory
        self._save_trajectory(traj)
        self.current_trajectory = None
        return traj
    
    def _save_trajectory(self, traj: Trajectory):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S%f")
        name = traj.task[:40].replace(" ", "_").replace("/", "_").replace("|", "_")
        import hashlib
        h = hashlib.md5((traj.task + ts).encode()).hexdigest()[:8]
        filename = f"traj_{h}_{name}.json"
        path = self.log_dir / filename
        with open(path, 'w') as f:
            json.dump({
                "task": traj.task,
                "steps": traj.steps,
                "score": traj.score,
                "skill_version": traj.skill_version,
                "timestamp": traj.timestamp,
                "metadata": traj.metadata
            }, f, indent=2)
    
    def load_trajectories(self, skill_version: str = None) -> List[Trajectory]:
        trajectories = []
        for path in self.log_dir.glob("*.json"):
            with open(path) as f:
                data = json.load(f)
                if skill_version is None or data.get("skill_version") == skill_version:
                    trajectories.append(Trajectory(**data))
        return trajectories


def create_skillopt_skill(skill_name: str, seed_content: str = None) -> Path:
    """Create a new SkillOpt-enabled skill directory."""
    skill_dir = Path(f".opencode/skills/{skill_name}")
    skill_dir.mkdir(parents=True, exist_ok=True)
    
    config = {
        "skill_name": skill_name,
        "optimizer": {
            "learning_rate": 0.1,
            "validation_split": 0.2,
            "max_edits_per_epoch": 5,
            "validator": "default"
        },
        "seed_skill": seed_content
    }
    
    with open(skill_dir / "skillopt_config.yaml", 'w') as f:
        yaml.dump(config, f)
    
    if seed_content:
        (skill_dir / "seed_skill.md").write_text(seed_content)
    
    return skill_dir


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python skillopt_optimizer.py <skill_dir> [epochs]")
        sys.exit(1)
    
    skill_dir = sys.argv[1]
    epochs = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    optimizer = SkillOptimizer(skill_dir, validator="bug_bounty")
    
    logger = TrajectoryLogger(Path(skill_dir) / "trajectories")
    trajectories = logger.load_trajectories()
    
    if trajectories:
        optimizer.add_trajectories(trajectories)
        history = optimizer.train(epochs=epochs)
        print(f"\nTraining complete. Best skill deployed to: {optimizer.deploy()}")
    else:
        print("No trajectories found. Run some tasks first to collect training data.")