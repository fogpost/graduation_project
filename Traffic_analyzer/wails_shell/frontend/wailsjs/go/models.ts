export namespace main {
	
	export class CaptureInterface {
	    index: number;
	    name: string;
	    description: string;
	    ips: string[];
	    status?: string;
	    speed?: string;
	    display: string;
	
	    static createFrom(source: any = {}) {
	        return new CaptureInterface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.ips = source["ips"];
	        this.status = source["status"];
	        this.speed = source["speed"];
	        this.display = source["display"];
	    }
	}
	export class TerminalEntry {
	    timestamp: string;
	    source: string;
	    line: string;
	
	    static createFrom(source: any = {}) {
	        return new TerminalEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.source = source["source"];
	        this.line = source["line"];
	    }
	}
	export class TerminalInfo {
	    id: string;
	    name: string;
	    type: string;
	    host?: string;
	    connected: boolean;
	    interactive: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TerminalInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.host = source["host"];
	        this.connected = source["connected"];
	        this.interactive = source["interactive"];
	    }
	}

}

