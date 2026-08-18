export type Dockyard = {
  id: number;
  name: string;
  description: string | null;
  status: string;
  created_at: string;
  updated_at: string;
};

export type Health = { status: string; service: string };
export type Version = { name: string; version: string };

